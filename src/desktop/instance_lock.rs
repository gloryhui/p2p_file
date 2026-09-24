use std::{
    fs::{File, OpenOptions},
    io,
    path::Path,
};

#[derive(Debug)]
pub struct InstanceLock {
    file: File,
}

#[derive(Debug, thiserror::Error)]
pub enum InstanceLockError {
    #[error("此数据目录已由另一个 P2P File 桌面实例使用")]
    AlreadyRunning,
    #[error("无法取得桌面实例锁：{0}")]
    Io(#[from] io::Error),
}

impl InstanceLock {
    pub fn acquire(path: &Path) -> Result<Self, InstanceLockError> {
        if let Some(parent) = path.parent() {
            super::config::ensure_private_app_dir(parent)?;
        }

        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        lock_file(&file).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                InstanceLockError::AlreadyRunning
            } else {
                InstanceLockError::Io(error)
            }
        })?;
        Ok(Self { file })
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        let _ = unlock_file(&self.file);
    }
}

#[cfg(unix)]
fn lock_file(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    const LOCK_EX: i32 = 2;
    const LOCK_NB: i32 = 4;
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    let result = unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn unlock_file(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    const LOCK_UN: i32 = 8;
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    let result = unsafe { flock(file.as_raw_fd(), LOCK_UN) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn lock_file(file: &File) -> io::Result<()> {
    use std::{ffi::c_void, os::windows::io::AsRawHandle};

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: *mut c_void,
    }

    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LockFileEx(
            file: *mut c_void,
            flags: u32,
            reserved: u32,
            bytes_low: u32,
            bytes_high: u32,
            overlapped: *mut Overlapped,
        ) -> i32;
    }

    let mut overlapped = Overlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        event: std::ptr::null_mut(),
    };
    let result = unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    if result != 0 {
        Ok(())
    } else {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(33) {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        } else {
            Err(error)
        }
    }
}

#[cfg(windows)]
fn unlock_file(file: &File) -> io::Result<()> {
    use std::{ffi::c_void, os::windows::io::AsRawHandle};

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: *mut c_void,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn UnlockFileEx(
            file: *mut c_void,
            reserved: u32,
            bytes_low: u32,
            bytes_high: u32,
            overlapped: *mut Overlapped,
        ) -> i32;
    }
    let mut overlapped = Overlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        event: std::ptr::null_mut(),
    };
    let result = unsafe { UnlockFileEx(file.as_raw_handle(), 0, 1, 0, &mut overlapped) };
    if result != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "p2p_file_instance_lock_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[test]
    fn one_data_directory_has_one_writer() {
        let dir = temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("instance.lock");
        let first = InstanceLock::acquire(&path).unwrap();
        assert!(matches!(
            InstanceLock::acquire(&path),
            Err(InstanceLockError::AlreadyRunning)
        ));
        drop(first);
        let second = InstanceLock::acquire(&path).unwrap();
        drop(second);
        fs::remove_dir_all(dir).unwrap();
    }
}
