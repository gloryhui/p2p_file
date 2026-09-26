//! Handle-relative filesystem operations. Remote names never become ambient paths.
use crate::error::{Error, Result};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use serde::{Deserialize, Serialize};
use std::{fs::File, io, path::Path};
use unicode_normalization::UnicodeNormalization;

pub fn fail(message: &str) -> Error {
    Error::Protocol(message.into())
}
pub fn name_key(name: &str) -> String {
    name.nfc().flat_map(char::to_lowercase).collect()
}

/// The explicitly configured/selected root is the ambient authority boundary.
/// Every component beneath it is resolved relative to an already-open directory.
pub fn root(path: &Path) -> Result<Dir> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(fail("目录或接收根不能是链接"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(fail("目录不能是 reparse point"));
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| fail("不能选择文件系统根目录"))?;
    let name = path.file_name().ok_or_else(|| fail("目录名称不可用"))?;
    let parent = Dir::open_ambient_dir(parent, cap_std::ambient_authority())?;
    Ok(parent.open_dir_nofollow(name)?)
}

pub fn reject_alias(dir: &Dir, name: &str) -> Result<()> {
    let key = name_key(name);
    for (count, entry) in dir.entries()?.enumerate() {
        if count >= 65_536 {
            return Err(fail("目录条目超过扫描上限"));
        }
        let existing = entry?.file_name();
        let Some(existing) = existing.to_str() else {
            return Err(fail("目录包含不支持的路径编码"));
        };
        if existing != name && name_key(existing) == key {
            return Err(fail("路径存在大小写或 Unicode 规范化冲突"));
        }
    }
    Ok(())
}

pub fn child(dir: &Dir, name: &str, create: bool) -> Result<Dir> {
    reject_alias(dir, name)?;
    if create {
        match dir.create_dir(name) {
            Ok(()) => {
                sync(dir)?;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    let next = dir.open_dir_nofollow(name)?;
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt;
        if next.dir_metadata()?.file_attributes() & 0x400 != 0 {
            return Err(fail("接收路径包含 reparse point"));
        }
    }
    Ok(next)
}

pub fn parent(root: &Dir, relative: &str, create: bool) -> Result<(Dir, String)> {
    super::protocol::validate_relative_path(relative)?;
    let mut parts = relative.split('/').collect::<Vec<_>>();
    let name = parts.pop().unwrap().to_owned();
    let mut dir = root.try_clone()?;
    for part in parts {
        dir = child(&dir, part, create)?;
    }
    reject_alias(&dir, &name)?;
    Ok((dir, name))
}

pub fn open(dir: &Dir, name: &str, write: bool, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(write)
        .create(create)
        .follow(FollowSymlinks::No);
    let file = dir.open_with(name, &options)?.into_std();
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(fail("存储条目不是普通文件"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(fail("存储条目是 reparse point"));
        }
    }
    Ok(file)
}

pub fn sync(dir: &Dir) -> Result<()> {
    #[cfg(unix)]
    dir.open(".")?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub volume: u64,
    pub index: u64,
}
#[cfg(unix)]
pub fn identity(file: &File) -> Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata()?;
    Ok(FileIdentity {
        volume: m.dev(),
        index: m.ino(),
    })
}
#[cfg(windows)]
pub fn identity(file: &File) -> Result<FileIdentity> {
    use std::os::windows::io::AsRawHandle;
    #[repr(C)]
    #[derive(Default)]
    struct Info {
        attributes: u32,
        creation: [u32; 2],
        access: [u32; 2],
        write: [u32; 2],
        volume: u32,
        size: [u32; 2],
        links: u32,
        index: [u32; 2],
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(handle: *mut std::ffi::c_void, info: *mut Info) -> i32;
    }
    let mut info = Info::default();
    // The file owns a live handle; Info matches BY_HANDLE_FILE_INFORMATION.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(FileIdentity {
        volume: u64::from(info.volume),
        index: (u64::from(info.index[0]) << 32) | u64::from(info.index[1]),
    })
}
#[cfg(not(any(unix, windows)))]
pub fn identity(_: &File) -> Result<FileIdentity> {
    Err(fail("此平台不支持文件身份"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn rename_no_replace(dir: &Dir, from: &str, to: &str) -> Result<()> {
    rustix::fs::renameat_with(dir, from, dir, to, rustix::fs::RenameFlags::NOREPLACE)
        .map_err(io::Error::from)?;
    Ok(())
}
#[cfg(windows)]
pub fn rename_no_replace(dir: &Dir, from: &str, to: &str) -> Result<()> {
    use cap_std::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    #[repr(C)]
    struct RenameInfo {
        replace: u32,
        root: *mut std::ffi::c_void,
        len: u32,
        name: [u16; 1],
    }
    #[repr(C)]
    struct IoStatusBlock {
        status_or_pointer: usize,
        information: usize,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtSetInformationFile(
            handle: *mut std::ffi::c_void,
            status: *mut IoStatusBlock,
            data: *const std::ffi::c_void,
            length: u32,
            class: i32,
        ) -> i32;
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .access_mode(0x00010000 | 0x00100000 | 0x80)
        .follow(FollowSymlinks::No);
    let file = dir.open_with(from, &options)?.into_std();
    let directory = dir.try_clone()?.into_std_file();
    let name = to.encode_utf16().collect::<Vec<_>>();
    let offset = std::mem::offset_of!(RenameInfo, name);
    let size = offset + (name.len() + 1) * 2;
    let mut buffer = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let data = buffer.as_mut_ptr().cast::<RenameInfo>();
    // Aligned storage covers header and variable UTF-16 name; replace=false.
    unsafe {
        (*data).replace = 0;
        (*data).root = directory.as_raw_handle();
        (*data).len = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            std::ptr::addr_of_mut!((*data).name).cast::<u16>(),
            name.len(),
        );
        let mut status = IoStatusBlock {
            status_or_pointer: 0,
            information: 0,
        };
        // Native FileRenameInformation supports a pinned relative RootDirectory;
        // the Win32 wrapper rejects this parameter combination on tested Windows.
        let result = NtSetInformationFile(
            file.as_raw_handle(),
            &mut status,
            data.cast(),
            size as u32,
            10,
        );
        if result < 0 {
            return Err(io::Error::from_raw_os_error(RtlNtStatusToDosError(result) as i32).into());
        }
    }
    Ok(())
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn rename_no_replace(_: &Dir, _: &str, _: &str) -> Result<()> {
    Err(fail("此平台不支持原子备份"))
}

pub fn atomic_json<T: Serialize>(dir: &Dir, name: &str, value: &T) -> Result<()> {
    use std::io::Write;
    let bytes = serde_json::to_vec(value).map_err(|_| fail("发布 journal 编码失败"))?;
    if bytes.len() > 64 * 1024 {
        return Err(fail("发布 journal 超限"));
    }
    let temp = format!("journal-{:032x}.tmp", rand::random::<u128>());
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut file = dir.open_with(&temp, &options)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    dir.rename(&temp, dir, name)?;
    sync(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs as ambient;
    fn fixture() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("p2p-secure-dir-{}", rand::random::<u128>()));
        ambient::create_dir(&path).unwrap();
        path
    }
    #[cfg(unix)]
    #[test]
    fn parent_and_internal_staging_symlink_cannot_escape_root() {
        use std::os::unix::fs::symlink;
        let path = fixture();
        let outside = fixture();
        symlink(&outside, path.join("nested")).unwrap();
        let dir = root(&path).unwrap();
        assert!(parent(&dir, "nested/secret", true).is_err());
        symlink(&outside, path.join(".p2p-desktop")).unwrap();
        assert!(child(&dir, ".p2p-desktop", true).is_err());
        assert_eq!(ambient::read_dir(&outside).unwrap().count(), 0);
        ambient::remove_dir_all(path).unwrap();
        ambient::remove_dir_all(outside).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn pinned_parent_survives_name_swap_without_following_replacement_link() {
        use std::os::unix::fs::symlink;
        let path = fixture();
        let outside = fixture();
        ambient::create_dir(path.join("nested")).unwrap();
        let dir = root(&path).unwrap();
        let (p, name) = parent(&dir, "nested/file", false).unwrap();
        ambient::rename(path.join("nested"), path.join("original")).unwrap();
        symlink(&outside, path.join("nested")).unwrap();
        let mut file = open(&p, &name, true, true).unwrap();
        use std::io::Write;
        file.write_all(b"authorized directory object").unwrap();
        assert_eq!(
            ambient::read(path.join("original/file")).unwrap(),
            b"authorized directory object"
        );
        assert!(!outside.join("file").exists());
        ambient::remove_dir_all(path).unwrap();
        ambient::remove_dir_all(outside).unwrap();
    }
    #[test]
    fn existing_alias_cannot_be_used_for_new_target_or_directory() {
        let path = fixture();
        ambient::create_dir(path.join("Named")).unwrap();
        let dir = root(&path).unwrap();
        assert!(parent(&dir, "named/file", true).is_err());
        ambient::write(path.join("é.txt"), []).unwrap();
        assert!(parent(&dir, "e\u{301}.txt", true).is_err());
        drop(dir);
        ambient::remove_dir_all(path).unwrap();
    }
}
