//! Native external-path batches. UI admission is pure; metadata runs off-thread.
use crate::error::Result;
use std::{
    collections::HashSet,
    path::{Component, PathBuf},
};
pub(super) const MAX_PATHS: usize = 128;
const MAX_PATH_BYTES: usize = 32_768;
const MAX_BATCH_BYTES: usize = 1024 * 1024;
#[derive(Clone, Copy, Default)]
pub(super) struct Admission {
    pub authorized: bool,
    pub storage_ready: bool,
    pub modal: bool,
    pub speed_busy: bool,
}
impl Admission {
    pub fn allowed(self) -> bool {
        self.authorized && self.storage_ready && !self.modal && !self.speed_busy
    }
}
pub(super) enum Selection {
    File(PathBuf),
    Directory(PathBuf),
}
impl Selection {
    fn path(&self) -> &PathBuf {
        match self {
            Self::File(path) | Self::Directory(path) => path,
        }
    }
}
pub(super) fn validate_paths(paths: &[PathBuf]) -> Result<()> {
    if paths.is_empty() || paths.len() > MAX_PATHS {
        return Err(super::transfer_files::failure(
            "每次拖入 1..128 个文件或目录",
        ));
    }
    let mut bytes = 0usize;
    for path in paths {
        let length = path.as_os_str().as_encoded_bytes().len();
        bytes = bytes.saturating_add(length);
        if length > MAX_PATH_BYTES || bytes > MAX_BATCH_BYTES {
            return Err(super::transfer_files::failure(
                "拖入路径过长或本批次路径总量超过 1 MiB",
            ));
        }
        if !path.is_absolute()
            || path.to_str().is_none()
            || path.file_name().is_none()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err(super::transfer_files::failure(
                "拖入项必须是绝对 UTF-8 文件或目录路径，不支持父目录跳转",
            ));
        }
    }
    Ok(())
}
pub(super) fn normalize(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    validate_paths(&paths)?;
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for path in paths {
        let normalized: PathBuf = path.components().collect();
        if seen.insert(normalized.clone()) {
            unique.push(normalized);
        }
    }
    Ok(unique)
}
pub(super) fn classify(paths: Vec<PathBuf>) -> Result<Vec<Selection>> {
    let mut selections = Vec::new();
    for path in normalize(paths)? {
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| {
            super::transfer_files::failure("拖入项已移走或无法访问；本批次尚未加入任务")
        })?;
        #[cfg(windows)]
        let reparse = {
            use std::os::windows::fs::MetadataExt;
            metadata.file_attributes() & 0x400 != 0
        };
        #[cfg(not(windows))]
        let reparse = false;
        if metadata.file_type().is_symlink() || reparse {
            return Err(super::transfer_files::failure(
                "拖入项不能是链接或 reparse point；本批次尚未加入任务",
            ));
        }
        selections.push(if metadata.is_file() {
            Selection::File(path)
        } else if metadata.is_dir() {
            Selection::Directory(path)
        } else {
            return Err(super::transfer_files::failure(
                "拖入项必须是普通文件或目录；本批次尚未加入任务",
            ));
        });
    }
    let directories: Vec<_> = selections
        .iter()
        .filter_map(|selection| match selection {
            Selection::Directory(path) => Some(path.clone()),
            _ => None,
        })
        .collect();
    selections.retain(|selection| {
        !directories
            .iter()
            .any(|parent| selection.path() != parent && selection.path().starts_with(parent))
    });
    Ok(selections)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_ui_admission_boundary_is_required() {
        let ready = Admission {
            authorized: true,
            storage_ready: true,
            modal: false,
            speed_busy: false,
        };
        assert!(ready.allowed());
        for blocked in [
            Admission {
                authorized: false,
                ..ready
            },
            Admission {
                storage_ready: false,
                ..ready
            },
            Admission {
                modal: true,
                ..ready
            },
            Admission {
                speed_busy: true,
                ..ready
            },
        ] {
            assert!(!blocked.allowed());
        }
    }
    #[test]
    fn normalization_is_bounded_and_does_not_expand_path_authority() {
        let root = std::env::temp_dir().join("p2p-drop-test");
        assert_eq!(
            normalize(vec![root.clone(), root.join(".")]).unwrap(),
            vec![root.clone()]
        );
        assert!(normalize(vec![]).is_err());
        assert!(validate_paths(&[root.join("x".repeat(MAX_PATH_BYTES + 1))]).is_err());
        assert!(
            validate_paths(&vec![root.join("x".repeat(MAX_PATH_BYTES / 2)); MAX_PATHS]).is_err()
        );
        assert!(normalize(vec![root.clone(); MAX_PATHS + 1]).is_err());
        assert!(normalize(vec![PathBuf::from("relative")]).is_err());
        assert!(normalize(vec![root.join("../outside")]).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            assert!(
                normalize(vec![PathBuf::from(std::ffi::OsString::from_vec(
                    b"/tmp/invalid-\xff".to_vec()
                ))])
                .is_err()
            );
        }
    }
    #[test]
    fn mixed_selection_deduplicates_overlapping_directories_before_scanning() {
        let root = std::env::temp_dir().join(format!("p2p-drop-{}", rand::random::<u128>()));
        std::fs::create_dir_all(root.join("目录/nested")).unwrap();
        std::fs::write(root.join("目录/nested/file.bin"), b"child").unwrap();
        std::fs::write(root.join("outside.bin"), b"other").unwrap();
        let selected = classify(vec![
            root.join("目录/nested/file.bin"),
            root.join("outside.bin"),
            root.join("目录"),
            root.join("目录/nested"),
            root.join("outside.bin"),
        ])
        .unwrap();
        assert_eq!(selected.len(), 2);
        assert!(matches!(&selected[0], Selection::File(path) if path == &root.join("outside.bin")));
        assert!(matches!(&selected[1], Selection::Directory(path) if path == &root.join("目录")));
        assert!(classify(vec![root.join("outside.bin"), root.join("missing")]).is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("outside.bin"), root.join("link")).unwrap();
            assert!(classify(vec![root.join("outside.bin"), root.join("link")]).is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
