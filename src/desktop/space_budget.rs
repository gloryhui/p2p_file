//! Advisory receive-space admission. Filesystem probes run on blocking workers;
//! the accounting mutex never spans a filesystem call. Reservations follow IO.
use crate::error::{Error, Result};
use cap_std::fs::Dir;
use std::{
    collections::{HashMap, HashSet},
    io,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU16, Ordering},
    },
};

pub(super) const DEFAULT_SAFETY_MIB: u16 = 64;
const MAX_SAFETY_MIB: u16 = 4096;
pub(super) const TASK_OVERHEAD: u64 = 64 * 1024;
const MAX_RESERVATIONS: usize = 64;

pub(super) fn default_safety_mib() -> u16 {
    DEFAULT_SAFETY_MIB
}
pub(super) fn validate_safety_mib(value: u16) -> std::result::Result<(), &'static str> {
    if value > MAX_SAFETY_MIB {
        Err("接收安全余量必须为 0..4096 MiB")
    } else {
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct Filesystem {
    volume: u64,
    // Windows mount aliases share the volume GUID. A network share without
    // a GUID falls back to its native volume serial (conservative collisions).
    namespace: Option<String>,
}
#[derive(Clone, Debug)]
pub(super) struct Probe {
    pub filesystem: Filesystem,
    pub available: u64,
}
#[derive(Debug, thiserror::Error)]
pub(super) enum SpaceError {
    #[error("接收磁盘空间不足（需要 {required} 字节，可用 {available} 字节）")]
    Insufficient { required: u64, available: u64 },
    #[error("无法检查接收文件系统的可用空间")]
    Unavailable,
    #[error("接收空间预算正忙，请稍后手动继续")]
    Busy,
    #[error("暂存目录和目标目录位于不同文件系统，无法原子发布")]
    CrossFilesystem,
}
impl SpaceError {
    pub(super) fn diagnostic(&self) -> super::task_model::TaskErrorCode {
        use super::task_model::TaskErrorCode;
        match self {
            Self::Insufficient { .. } => TaskErrorCode::DiskFull,
            Self::Unavailable => TaskErrorCode::SpaceCheckUnavailable,
            Self::Busy => TaskErrorCode::ReceiveBudgetBusy,
            Self::CrossFilesystem => TaskErrorCode::FilesystemMismatch,
        }
    }
    pub(super) fn error(self) -> Error {
        let kind = if matches!(self, Self::Insufficient { .. }) {
            io::ErrorKind::StorageFull
        } else {
            io::ErrorKind::Other
        };
        Error::Io(io::Error::new(kind, self))
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Summary {
    pub reserved: u64,
    pub filesystems: usize,
}
#[derive(Default)]
struct Accounts {
    version: u64,
    nonce: u64,
    reservations: HashMap<u64, (Filesystem, u64)>,
}
#[derive(Clone)]
pub(super) struct SpaceBudget {
    accounts: Arc<Mutex<Accounts>>,
    safety_mib: Arc<AtomicU16>,
    #[cfg(test)]
    pub(super) probe_override: Arc<Mutex<Option<std::result::Result<u64, ()>>>>,
}
impl Default for SpaceBudget {
    fn default() -> Self {
        Self {
            accounts: Default::default(),
            safety_mib: Arc::new(AtomicU16::new(DEFAULT_SAFETY_MIB)),
            #[cfg(test)]
            probe_override: Default::default(),
        }
    }
}
impl SpaceBudget {
    pub fn set_safety_mib(&self, value: u16) -> Result<()> {
        validate_safety_mib(value).map_err(super::transfer_files::failure)?;
        self.safety_mib.store(value, Ordering::Release);
        Ok(())
    }
    pub fn summary(&self) -> Summary {
        let accounts = self.accounts.lock().unwrap();
        Summary {
            reserved: accounts
                .reservations
                .values()
                .fold(0u64, |sum, (_, bytes)| sum.saturating_add(*bytes)),
            filesystems: accounts
                .reservations
                .values()
                .map(|(volume, _)| volume)
                .collect::<HashSet<_>>()
                .len(),
        }
    }
    pub fn reserve_file(
        &self,
        record: &super::task_model::TaskRecord,
        staging: &Dir,
        remaining: u64,
    ) -> Result<Reservation> {
        let target = destination_filesystem(record)?;
        if probe(staging)?.filesystem != probe(&target)?.filesystem {
            return Err(SpaceError::CrossFilesystem.error());
        }
        let bytes = remaining
            .checked_add(TASK_OVERHEAD)
            .ok_or_else(|| SpaceError::Unavailable.error())?;
        self.reserve(staging, bytes)
    }
    pub fn reserve_directory(&self, record: &super::task_model::TaskRecord) -> Result<Reservation> {
        self.reserve(&destination_filesystem(record)?, TASK_OVERHEAD)
    }
    pub fn reserve(&self, directory: &Dir, bytes: u64) -> Result<Reservation> {
        self.reserve_with_probe(
            || {
                #[cfg(test)]
                if self
                    .probe_override
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|p| p.is_err())
                {
                    return Err(SpaceError::Unavailable.error());
                }
                let mut result = probe(directory)?;
                #[cfg(test)]
                if let Some(Ok(available)) = *self.probe_override.lock().unwrap() {
                    result.available = available;
                }
                // Keep the test override local to this service, never in globals.
                let _ = &mut result;
                Ok(result)
            },
            bytes,
        )
    }
    fn reserve_with_probe(
        &self,
        mut probe: impl FnMut() -> Result<Probe>,
        bytes: u64,
    ) -> Result<Reservation> {
        // Progress/release changes invalidate an older free-space snapshot.
        // Retrying outside the mutex avoids blocking reactor/UI in RAII Drop.
        for _ in 0..4 {
            let version = self.accounts.lock().unwrap().version;
            let space = probe()?;
            let mut accounts = self.accounts.lock().unwrap();
            if accounts.version != version {
                continue;
            }
            if accounts.reservations.len() >= MAX_RESERVATIONS {
                return Err(SpaceError::Busy.error());
            }
            let held = accounts
                .reservations
                .values()
                .filter(|(fs, _)| fs == &space.filesystem)
                .try_fold(0u64, |sum, (_, bytes)| sum.checked_add(*bytes))
                .ok_or_else(|| SpaceError::Unavailable.error())?;
            let required = held
                .checked_add(bytes)
                .and_then(|n| {
                    n.checked_add(u64::from(self.safety_mib.load(Ordering::Acquire)) * 1024 * 1024)
                })
                .ok_or_else(|| SpaceError::Unavailable.error())?;
            if required > space.available {
                return Err(SpaceError::Insufficient {
                    required,
                    available: space.available,
                }
                .error());
            }
            accounts.nonce = accounts.nonce.wrapping_add(1);
            let nonce = accounts.nonce;
            accounts
                .reservations
                .insert(nonce, (space.filesystem, bytes));
            accounts.version = accounts.version.wrapping_add(1);
            return Ok(Reservation(Arc::new(Lease {
                accounts: self.accounts.clone(),
                nonce,
                keep_alive: OnceLock::new(),
            })));
        }
        Err(SpaceError::Busy.error())
    }
}
#[derive(Clone)]
pub(super) struct Reservation(Arc<Lease>);
struct Lease {
    accounts: Arc<Mutex<Accounts>>,
    nonce: u64,
    keep_alive: OnceLock<Arc<dyn Send + Sync>>,
}
impl Reservation {
    pub fn keep_alive(&self, owner: Arc<dyn Send + Sync>) {
        let _ = self.0.keep_alive.set(owner);
    }
    // Called by the blocking write worker after actual writes, not before IO.
    pub fn written(&self, bytes: u64) {
        let mut accounts = self.0.accounts.lock().unwrap();
        if let Some((_, remaining)) = accounts.reservations.get_mut(&self.0.nonce) {
            *remaining = remaining.saturating_sub(bytes).max(TASK_OVERHEAD);
            accounts.version = accounts.version.wrapping_add(1);
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut accounts = self.accounts.lock().unwrap();
        accounts.reservations.remove(&self.nonce);
        accounts.version = accounts.version.wrapping_add(1);
    }
}

// Query the deepest existing directory through the same no-follow authority
// as publication. New descendants inherit its filesystem; no ambient join.
fn destination_filesystem(record: &super::task_model::TaskRecord) -> Result<Dir> {
    let relative = record
        .relative_path()
        .ok_or_else(|| SpaceError::Unavailable.error())?;
    super::protocol::validate_relative_path(relative)?;
    let mut directory = super::secure_fs::root(record.local_path())?;
    let mut parts: Vec<_> = relative.split('/').collect();
    if record.file_details().is_some() {
        parts.pop();
    }
    for name in parts {
        match super::secure_fs::child(&directory, name, false) {
            Ok(next) => directory = next,
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => break,
            Err(e) => return Err(e),
        }
    }
    Ok(directory)
}

#[cfg(unix)]
pub(super) fn probe(directory: &Dir) -> Result<Probe> {
    let file = directory.try_clone()?.into_std_file();
    let identity = super::secure_fs::identity(&file)?;
    let stats = rustix::fs::fstatvfs(&file).map_err(|_| SpaceError::Unavailable.error())?;
    if stats.f_frsize == 0 {
        return Err(SpaceError::Unavailable.error());
    }
    Ok(Probe {
        filesystem: Filesystem {
            volume: identity.volume,
            namespace: None,
        },
        available: stats
            .f_bavail
            .checked_mul(stats.f_frsize)
            .ok_or_else(|| SpaceError::Unavailable.error())?,
    })
}
#[cfg(windows)]
pub(super) fn probe(directory: &Dir) -> Result<Probe> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetDiskFreeSpaceExW, GetFinalPathNameByHandleW, VOLUME_NAME_DOS, VOLUME_NAME_GUID,
    };
    let file = directory.try_clone()?.into_std_file();
    let identity = super::secure_fs::identity(&file)?;
    let mut path = vec![0u16; 1024];
    let mut guid = true;
    loop {
        // The directory owns this live handle; the buffer and length agree.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                path.as_mut_ptr(),
                path.len() as u32,
                if guid {
                    VOLUME_NAME_GUID
                } else {
                    VOLUME_NAME_DOS
                },
            )
        } as usize;
        if length == 0 {
            if guid {
                guid = false;
                continue;
            }
            return Err(SpaceError::Unavailable.error());
        }
        if length >= path.len() {
            if length > 65536 {
                return Err(SpaceError::Unavailable.error());
            }
            path.resize(length + 1, 0);
            continue;
        }
        path.truncate(length);
        break;
    }
    let namespace = if guid {
        let end = path
            .iter()
            .position(|c| *c == b'}' as u16)
            .ok_or_else(|| SpaceError::Unavailable.error())?;
        path.truncate(end + 1);
        Some(String::from_utf16_lossy(&path).to_ascii_lowercase())
    } else {
        None
    };
    // A volume GUID avoids a renamed/mount-alias path; UNC names require '\\'.
    if path.last() != Some(&(b'\\' as u16)) {
        path.push(b'\\' as u16);
    }
    path.push(0);
    let mut available = 0u64;
    // Use caller-available bytes (quotas), keeping all values at 64 bits.
    if unsafe {
        GetDiskFreeSpaceExW(
            path.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(SpaceError::Unavailable.error());
    }
    Ok(Probe {
        filesystem: Filesystem {
            volume: identity.volume,
            namespace,
        },
        available,
    })
}
#[cfg(not(any(unix, windows)))]
pub(super) fn probe(_: &Dir) -> Result<Probe> {
    Err(SpaceError::Unavailable.error())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fs(volume: u64) -> Filesystem {
        Filesystem {
            volume,
            namespace: None,
        }
    }
    fn budget() -> SpaceBudget {
        let budget = SpaceBudget::default();
        budget.set_safety_mib(0).unwrap();
        budget
    }
    fn reserve(
        budget: &SpaceBudget,
        volume: u64,
        available: u64,
        bytes: u64,
    ) -> Result<Reservation> {
        budget.reserve_with_probe(
            || {
                Ok(Probe {
                    filesystem: fs(volume),
                    available,
                })
            },
            bytes,
        )
    }
    #[test]
    fn one_margin_and_shared_reservations_per_filesystem() {
        let budget = SpaceBudget::default();
        let margin = u64::from(DEFAULT_SAFETY_MIB) * 1024 * 1024;
        let first = reserve(&budget, 1, margin + 200, 100).unwrap();
        let second = reserve(&budget, 1, margin + 200, 100).unwrap();
        assert!(reserve(&budget, 1, margin + 200, 1).is_err());
        let other = reserve(&budget, 2, margin + 100, 100).unwrap();
        assert_eq!(budget.summary().filesystems, 2);
        drop(first);
        drop(second);
        drop(other);
        assert_eq!(budget.summary().reserved, 0);
        assert_eq!(budget.summary().filesystems, 0);
    }
    #[test]
    fn writes_reduce_future_demand_and_old_probes_are_retried() {
        let budget = budget();
        let first = reserve(&budget, 1, TASK_OVERHEAD + 1000, TASK_OVERHEAD + 1000).unwrap();
        let mut probes = 0;
        let second = budget
            .reserve_with_probe(
                || {
                    probes += 1;
                    if probes == 1 {
                        first.written(500);
                    }
                    Ok(Probe {
                        filesystem: fs(1),
                        available: 2 * TASK_OVERHEAD + 500,
                    })
                },
                TASK_OVERHEAD,
            )
            .unwrap();
        assert_eq!(probes, 2);
        assert_eq!(budget.summary().reserved, 2 * TASK_OVERHEAD + 500);
        first.written(u64::MAX);
        assert_eq!(budget.summary().reserved, 2 * TASK_OVERHEAD);
        drop((first, second));
        assert_eq!(budget.summary().reserved, 0);
    }
    #[test]
    fn outstanding_io_clone_keeps_budget_and_owner_until_quiescent() {
        struct Owner(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Owner {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let budget = budget();
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reservation = reserve(&budget, 1, TASK_OVERHEAD, TASK_OVERHEAD).unwrap();
        reservation.keep_alive(Arc::new(Owner(released.clone())));
        let io = reservation.clone();
        drop(reservation);
        assert_eq!(budget.summary().reserved, TASK_OVERHEAD);
        assert!(!released.load(Ordering::Acquire));
        drop(io);
        assert_eq!(budget.summary().reserved, 0);
        assert!(released.load(Ordering::Acquire));
    }
    #[test]
    fn concurrent_admission_cannot_oversubscribe_the_shared_space() {
        let budget = budget();
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let budget = budget.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    reserve(&budget, 1, TASK_OVERHEAD * 3, TASK_OVERHEAD).ok()
                })
            })
            .collect();
        let held: Vec<_> = threads
            .into_iter()
            .filter_map(|thread| thread.join().unwrap())
            .collect();
        assert!(held.len() <= 3);
        assert_eq!(budget.summary().reserved, held.len() as u64 * TASK_OVERHEAD);
        drop(held);
        assert_eq!(budget.summary().reserved, 0);
    }
    #[test]
    fn query_failure_overflow_churn_capacity_and_invalid_margin_fail_closed() {
        let budget = budget();
        assert!(budget.set_safety_mib(4097).is_err());
        assert!(
            budget
                .reserve_with_probe(|| Err(SpaceError::Unavailable.error()), 1)
                .is_err()
        );
        budget.set_safety_mib(1).unwrap();
        assert!(reserve(&budget, 1, u64::MAX, u64::MAX).is_err());
        budget.set_safety_mib(0).unwrap();
        let held: Vec<_> = (0..MAX_RESERVATIONS)
            .map(|_| reserve(&budget, 1, u64::MAX, TASK_OVERHEAD).unwrap())
            .collect();
        assert!(reserve(&budget, 1, u64::MAX, 1).is_err());
        drop(held);
        let first = reserve(&budget, 1, u64::MAX, TASK_OVERHEAD + 10).unwrap();
        assert!(
            budget
                .reserve_with_probe(
                    || {
                        first.written(1);
                        Ok(Probe {
                            filesystem: fs(1),
                            available: u64::MAX,
                        })
                    },
                    1
                )
                .is_err()
        );
        drop(first);
        assert_eq!(budget.summary().reserved, 0);
    }
    #[test]
    fn native_probe_uses_the_open_directory_and_unifies_siblings() {
        let path = std::env::temp_dir().join(format!("p2p-space-probe-{}", rand::random::<u128>()));
        std::fs::create_dir(&path).unwrap();
        std::fs::create_dir(path.join("child")).unwrap();
        let parent = super::super::secure_fs::root(&path).unwrap();
        let child = super::super::secure_fs::child(&parent, "child", false).unwrap();
        let one = probe(&parent).unwrap();
        let two = probe(&child).unwrap();
        assert_eq!(one.filesystem, two.filesystem);
        assert!(one.available > 0);
        drop((parent, child));
        std::fs::remove_dir_all(path).unwrap();
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_different_actual_filesystems_have_independent_budgets() {
        let ordinary =
            Dir::open_ambient_dir(std::env::temp_dir(), cap_std::ambient_authority()).unwrap();
        let memory = Dir::open_ambient_dir("/dev/shm", cap_std::ambient_authority()).unwrap();
        let one = probe(&ordinary).unwrap();
        let two = probe(&memory).unwrap();
        assert_ne!(one.filesystem, two.filesystem);
        let budget = budget();
        let first = budget.reserve(&ordinary, TASK_OVERHEAD).unwrap();
        let second = budget.reserve(&memory, 1).unwrap();
        assert_eq!(budget.summary().filesystems, 2);
        drop((first, second));
    }
}
