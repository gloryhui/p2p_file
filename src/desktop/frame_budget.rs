//! Bounded application frame memory. Reservations precede allocation and remain
//! attached to decoded frames until the task finishes processing them.
use super::protocol::{Frame, MAX_FRAME_BYTES};
use super::transfer_files::{failure, local_error};
use crate::error::Result;
use std::sync::Arc;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    sync::{OwnedSemaphorePermit, Semaphore},
};

pub const UNIT: usize = 64 * 1024;
pub const GLOBAL_BYTES: usize = 64 * 1024 * 1024;
pub const DATA_BYTES: usize = 56 * 1024 * 1024;
pub const TASK_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct FrameBudget {
    all: Arc<Semaphore>,
    data: Arc<Semaphore>,
}
impl Default for FrameBudget {
    fn default() -> Self {
        Self {
            all: Arc::new(Semaphore::new(GLOBAL_BYTES / UNIT)),
            data: Arc::new(Semaphore::new(DATA_BYTES / UNIT)),
        }
    }
}
pub struct FrameLease {
    _data: Option<OwnedSemaphorePermit>,
    _all: OwnedSemaphorePermit,
    _task: Option<OwnedSemaphorePermit>,
}
pub struct BufferedFrame {
    pub frame: Frame,
    pub _lease: FrameLease,
}
impl FrameBudget {
    pub fn task_limit() -> Arc<Semaphore> {
        Arc::new(Semaphore::new(TASK_BYTES / UNIT))
    }
    async fn reserve(&self, length: usize, task: Option<Arc<Semaphore>>) -> Result<FrameLease> {
        if length == 0 || length > MAX_FRAME_BYTES as usize {
            return Err(failure("桌面帧长度超出资源上限"));
        }
        // Raw bytes and decoded payload can coexist during deserialization.
        let units = (length * 2).div_ceil(UNIT) as u32;
        let task = match task {
            Some(task) => Some(task.acquire_many_owned(units).await.map_err(local_error)?),
            None => None,
        };
        // Large frames cannot consume the small-control reserve. Acquire this
        // before the global budget, so a waiting data stream holds no global bytes.
        let data = if length >= UNIT {
            Some(
                self.data
                    .clone()
                    .acquire_many_owned(units)
                    .await
                    .map_err(local_error)?,
            )
        } else {
            None
        };
        let all = self
            .all
            .clone()
            .acquire_many_owned(units)
            .await
            .map_err(local_error)?;
        Ok(FrameLease {
            _data: data,
            _all: all,
            _task: task,
        })
    }
    pub async fn read<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        task: Option<Arc<Semaphore>>,
    ) -> Result<BufferedFrame> {
        let length = reader.read_u32_le().await? as usize;
        let lease = self.reserve(length, task).await?;
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes).await?;
        let frame = Frame::decode(&bytes)?;
        Ok(BufferedFrame {
            frame,
            _lease: lease,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn global_data_cap_leaves_control_room_and_cancel_returns_every_permit() {
        let budget = FrameBudget::default();
        let mut held = Vec::new();
        for _ in 0..7 {
            held.push(
                budget
                    .reserve(MAX_FRAME_BYTES as usize, None)
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(budget.data.available_permits(), 0);
        let waiting = budget.clone();
        let blocked =
            tokio::spawn(async move { waiting.reserve(MAX_FRAME_BYTES as usize, None).await });
        tokio::task::yield_now().await;
        assert!(!blocked.is_finished());
        let control = budget.reserve(1024, None).await.unwrap();
        assert_eq!(
            budget.all.available_permits(),
            (GLOBAL_BYTES - DATA_BYTES) / UNIT - 1
        );
        blocked.abort();
        let _ = blocked.await;
        drop(control);
        drop(held);
        assert_eq!(budget.all.available_permits(), GLOBAL_BYTES / UNIT);
        assert_eq!(budget.data.available_permits(), DATA_BYTES / UNIT);
    }
    #[tokio::test]
    async fn per_task_cap_and_invalid_header_do_not_allocate_or_leak() {
        let budget = FrameBudget::default();
        let task = FrameBudget::task_limit();
        let held = budget
            .reserve(MAX_FRAME_BYTES as usize, Some(task.clone()))
            .await
            .unwrap();
        let second = budget.reserve(1, Some(task.clone()));
        tokio::pin!(second);
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(second.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(held);
        let next = second.await.unwrap();
        drop(next);
        assert_eq!(task.available_permits(), TASK_BYTES / UNIT);
        let mut reader = &(MAX_FRAME_BYTES + 1).to_le_bytes()[..];
        assert!(budget.read(&mut reader, Some(task)).await.is_err());
        assert_eq!(budget.all.available_permits(), GLOBAL_BYTES / UNIT);
    }
    #[tokio::test]
    async fn decoded_payload_keeps_budget_until_processing_and_bad_body_releases_it() {
        use super::super::{
            protocol::{self, Message},
            task_model::TaskId,
        };
        let budget = FrameBudget::default();
        let task = FrameBudget::task_limit();
        let frame = Frame {
            request_id: 1,
            message: Message::Chunk {
                task_id: TaskId::generate(),
                index: 0,
                data: vec![7; 1024 * 1024],
            },
        };
        let encoded = frame.encode().unwrap();
        let units = (encoded.len() * 2).div_ceil(UNIT);
        let mut wire = (encoded.len() as u32).to_le_bytes().to_vec();
        wire.extend_from_slice(&encoded);
        let decoded = budget
            .read(&mut &wire[..], Some(task.clone()))
            .await
            .unwrap();
        assert_eq!(decoded.frame, frame);
        assert_eq!(task.available_permits(), TASK_BYTES / UNIT - units);
        assert_eq!(budget.all.available_permits(), GLOBAL_BYTES / UNIT - units);
        drop(decoded);
        assert_eq!(budget.all.available_permits(), GLOBAL_BYTES / UNIT);
        let bad = [1, 0, 0, 0, 255];
        assert!(
            budget
                .read(&mut &bad[..], Some(task.clone()))
                .await
                .is_err()
        );
        assert_eq!(task.available_permits(), TASK_BYTES / UNIT);
        assert_eq!(budget.all.available_permits(), GLOBAL_BYTES / UNIT);
        // Ordinary small control frames use the same bounded wire decoder.
        let frame = Frame {
            request_id: 1,
            message: Message::Pause {
                task_id: TaskId::generate(),
            },
        };
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        protocol::write(&mut writer, &frame).await.unwrap();
        assert_eq!(
            budget.read(&mut reader, Some(task)).await.unwrap().frame,
            frame
        );
    }
}
