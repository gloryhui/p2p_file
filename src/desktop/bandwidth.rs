//! One FIFO byte budget per direction, shared by every file task and peer.
//! Only a small bounded credit survives idle time; dropping a waiter holds no slot.
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::{
    sync::{Mutex as AsyncMutex, watch},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileLimits {
    pub upload_kib: u32,
    pub download_kib: u32,
}
impl FileLimits {
    pub fn validate(self) -> Result<(), &'static str> {
        if self.upload_kib > 1_048_576 || self.download_kib > 1_048_576 {
            Err("文件限速须为 0～1048576 KiB/s；0 表示不限速")
        } else {
            Ok(())
        }
    }
    pub fn parse(upload: &str, download: &str) -> Result<Self, &'static str> {
        let limits = Self {
            upload_kib: upload
                .trim()
                .parse()
                .map_err(|_| "上传限速须为非负整数 KiB/s")?,
            download_kib: download
                .trim()
                .parse()
                .map_err(|_| "下载限速须为非负整数 KiB/s")?,
        };
        limits.validate()?;
        Ok(limits)
    }
}
#[derive(Clone)]
pub struct ByteLimit {
    inner: Arc<Mutex<Bucket>>,
    turn: Arc<AsyncMutex<()>>,
    changed: watch::Sender<u64>,
}
struct Bucket {
    rate: u64,
    credit: f64,
    updated: Instant,
}
impl Default for ByteLimit {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Bucket {
                rate: 0,
                credit: 0.,
                updated: Instant::now(),
            })),
            turn: Arc::new(AsyncMutex::new(())),
            changed: watch::channel(0).0,
        }
    }
}
impl ByteLimit {
    pub fn set_kib(&self, value: u32) {
        let mut state = self.inner.lock().unwrap();
        let rate = u64::from(value) * 1024;
        if state.rate == rate {
            return;
        }
        state.rate = rate;
        state.credit = 0.;
        state.updated = Instant::now();
        self.changed.send_modify(|v| *v = v.wrapping_add(1));
    }
    pub fn enabled(&self) -> bool {
        self.inner.lock().unwrap().rate != 0
    }
    /// Grants at most 10ms of budget, so a large frame cannot monopolize the
    /// FIFO. Pausing bypasses the remainder of the bounded in-flight frame,
    /// allowing the existing durable pause handshake to finish promptly.
    pub async fn acquire(&self, maximum: usize, pause: &mut watch::Receiver<bool>) -> usize {
        if maximum == 0 {
            return 0;
        }
        let mut changed = self.changed.subscribe();
        loop {
            if *pause.borrow() {
                return maximum;
            }
            if !self.enabled() {
                return maximum.min(16 * 1024);
            }
            let guard = tokio::select! {
                guard = self.turn.lock() => guard,
                _ = pause.changed() => return maximum,
                _ = changed.changed() => continue,
            };
            loop {
                let (amount, wait) = {
                    let mut state = self.inner.lock().unwrap();
                    if state.rate == 0 {
                        return maximum.min(16 * 1024);
                    }
                    let now = Instant::now();
                    state.credit = (state.credit
                        + now.duration_since(state.updated).as_secs_f64() * state.rate as f64)
                        .min(state.rate as f64 / 10.);
                    state.updated = now;
                    let amount = maximum
                        .min(16 * 1024)
                        .min((state.rate / 100).max(1) as usize);
                    let wait = (amount as f64 - state.credit).max(0.) / state.rate as f64;
                    if wait == 0. {
                        state.credit -= amount as f64;
                    }
                    (amount, Duration::from_secs_f64(wait))
                };
                if wait.is_zero() {
                    return amount;
                }
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {},
                    _ = pause.changed() => return maximum,
                    _ = changed.changed() => break,
                }
            }
            drop(guard);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn shared_budget_is_bounded_and_runtime_changes_wake_waiters() {
        let limit = ByteLimit::default();
        limit.set_kib(10);
        let (_tx, mut rx) = watch::channel(false);
        let start = Instant::now();
        let mut received = 0;
        while received < 1024 {
            received += limit.acquire(1024 - received, &mut rx).await;
        }
        assert!(start.elapsed() >= Duration::from_millis(100));
        tokio::time::sleep(Duration::from_secs(100)).await;
        let start = Instant::now();
        let mut burst = 0;
        while start.elapsed() < Duration::from_millis(100) {
            burst += limit.acquire(1024, &mut rx).await;
        }
        assert!(
            burst <= 2048 + 102,
            "idle credit must stay bounded: {burst}"
        );
        limit.set_kib(1);
        let other = limit.clone();
        let waiter = tokio::spawn(async move { other.acquire(16 * 1024, &mut rx).await });
        tokio::task::yield_now().await;
        limit.set_kib(0);
        assert_eq!(waiter.await.unwrap(), 16 * 1024);
    }
    #[tokio::test(start_paused = true)]
    async fn fifo_tasks_share_one_budget_and_cancel_returns_the_turn() {
        let limit = ByteLimit::default();
        limit.set_kib(10);
        let start = Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..3 {
            let limit = limit.clone();
            tasks.spawn(async move {
                let (_tx, mut rx) = watch::channel(false);
                let mut bytes = 0;
                while bytes < 1024 {
                    bytes += limit.acquire(1024 - bytes, &mut rx).await;
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert!(start.elapsed() >= Duration::from_millis(300));
        limit.set_kib(1);
        let other = limit.clone();
        let waiter = tokio::spawn(async move {
            let (_tx, mut rx) = watch::channel(false);
            other.acquire(1024, &mut rx).await
        });
        tokio::task::yield_now().await;
        waiter.abort();
        let _ = waiter.await;
        let (tx, mut rx) = watch::channel(false);
        tx.send_replace(true);
        assert_eq!(limit.acquire(1024 * 1024, &mut rx).await, 1024 * 1024);
    }
    #[test]
    fn input_validation_has_explicit_units_and_zero_is_unlimited() {
        assert_eq!(FileLimits::parse("0", " 1024 ").unwrap().download_kib, 1024);
        for bad in ["-1", "", "1.5", "1048577", "4294967296"] {
            assert!(FileLimits::parse(bad, "0").is_err());
        }
    }
}
