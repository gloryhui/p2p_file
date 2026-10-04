//! Directory comparison and proof of existing content. All IO runs on workers.
use super::{
    protocol::Difference,
    secure_fs as fs,
    task_model::{TaskId, TaskRecord},
};
use crate::{
    error::{Error, Result},
    identity::NodeId,
    protocol::manifest::FileManifest,
    transfer::chunker::manifest_from_reader,
};
use cap_std::fs::Dir;
use std::{
    fs::File,
    io::{self, Read},
    path::PathBuf,
    time::{Duration, Instant, SystemTime},
};

pub const COMPARE_TIMEOUT: Duration = Duration::from_secs(120);
pub const PREVIEW_LIFETIME: Duration = Duration::from_secs(300);

#[derive(Clone, Debug)]
pub struct Preview {
    pub id: TaskId,
    pub peer: NodeId,
    pub source: PathBuf,
    pub added: usize,
    pub changed: usize,
    pub unchanged: usize,
    pub directories: usize,
    pub transfer_bytes: u64,
    pub saved_bytes: u64,
    pub supported: bool,
}
pub(super) struct Request {
    pub id: TaskId,
    pub created: Instant,
    pub cancellation: super::files::ScanCancellation,
}
pub(super) struct Pending {
    pub summary: Preview,
    pub records: Vec<TaskRecord>,
    pub connection: usize,
    pub epoch: u64,
    pub created: Instant,
}

struct TimedReader<R> {
    reader: R,
    deadline: Instant,
}
impl<R: Read> Read for TimedReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "目录内容比较超时"));
        }
        self.reader.read(bytes)
    }
}

/// Retain no-follow handles across hashing and the durable receipt commit.
pub(super) struct Proof {
    root_path: PathBuf,
    relative: String,
    root: Dir,
    parent: Dir,
    name: String,
    file: File,
    identity: fs::FileIdentity,
    length: u64,
    modified: SystemTime,
}
impl Proof {
    pub fn revalidate(&self) -> Result<()> {
        let root = fs::root(&self.root_path)?;
        let (parent, name) = fs::parent(&root, &self.relative, false)?;
        if fs::identity(&root.into_std_file())?
            != fs::identity(&self.root.try_clone()?.into_std_file())?
            || fs::identity(&parent.try_clone()?.into_std_file())?
                != fs::identity(&self.parent.try_clone()?.into_std_file())?
            || name != self.name
        {
            return Err(fs::fail("比较期间接收路径身份已变化"));
        }
        let current = fs::open(&parent, &name, false, false)?;
        let metadata = current.metadata()?;
        if fs::identity(&current)? != self.identity
            || metadata.len() != self.length
            || metadata.modified()? != self.modified
        {
            return Err(fs::fail("比较期间接收文件已变化"));
        }
        Ok(())
    }
    pub fn make_durable(&self) -> Result<()> {
        self.revalidate()?;
        #[cfg(not(windows))]
        self.file.sync_all()?;
        #[cfg(windows)]
        {
            // FlushFileBuffers requires a write-capable handle. Never truncate.
            let writable = fs::open(&self.parent, &self.name, true, false)?;
            if fs::identity(&writable)? != self.identity {
                return Err(fs::fail("比较期间接收文件已变化"));
            }
            writable.sync_all()?;
        }
        fs::sync(&self.parent)?;
        self.revalidate()
    }
}

pub(super) fn compare(
    root_path: PathBuf,
    relative: String,
    manifest: FileManifest,
) -> Result<(Difference, Option<Proof>)> {
    super::transfer_files::validate_single_file(&manifest, &relative)?;
    let root = fs::root(&root_path)?;
    let (parent, name) = match fs::parent(&root, &relative, false) {
        Ok(result) => result,
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
            return Ok((Difference::Added, None));
        }
        Err(e) => return Err(e),
    };
    let file = match fs::open(&parent, &name, false, false) {
        Ok(file) => file,
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
            return Ok((Difference::Added, None));
        }
        Err(e) => return Err(e),
    };
    let metadata = file.metadata()?;
    if metadata.len() != manifest.total_len {
        return Ok((Difference::Changed, None));
    }
    let proof = Proof {
        root_path,
        relative,
        root,
        parent,
        name,
        identity: fs::identity(&file)?,
        length: metadata.len(),
        modified: metadata.modified()?,
        file,
    };
    let mut reader = TimedReader {
        reader: std::io::BufReader::new(
            proof
                .file
                .try_clone()?
                .take(manifest.total_len.saturating_add(1)),
        ),
        deadline: Instant::now() + COMPARE_TIMEOUT,
    };
    let current = manifest_from_reader(&manifest.file_name, manifest.chunk_size, &mut reader)?;
    proof.revalidate()?;
    if current == manifest {
        Ok((Difference::Unchanged, Some(proof)))
    } else {
        Ok((Difference::Changed, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::manifest::DEFAULT_CHUNK_SIZE;
    fn fixture() -> (PathBuf, FileManifest) {
        let root = std::env::temp_dir().join(format!("p2p-incremental-{}", TaskId::generate()));
        std::fs::create_dir_all(root.join("目录")).unwrap();
        std::fs::write(root.join("目录/a.txt"), b"same").unwrap();
        let manifest =
            manifest_from_reader("a.txt", DEFAULT_CHUNK_SIZE, &mut &b"same"[..]).unwrap();
        (root, manifest)
    }
    #[test]
    fn incremental_comparison_preserves_files_and_requires_content_hash() {
        let (root, manifest) = fixture();
        let (difference, proof) =
            compare(root.clone(), "目录/a.txt".into(), manifest.clone()).unwrap();
        assert_eq!(difference, Difference::Unchanged);
        proof.unwrap().make_durable().unwrap();
        std::fs::write(root.join("目录/a.txt"), b"diff").unwrap();
        assert_eq!(
            compare(root.clone(), "目录/a.txt".into(), manifest.clone())
                .unwrap()
                .0,
            Difference::Changed
        );
        std::fs::remove_file(root.join("目录/a.txt")).unwrap();
        assert_eq!(
            compare(root.clone(), "目录/a.txt".into(), manifest)
                .unwrap()
                .0,
            Difference::Added
        );
        assert_eq!(std::fs::read_dir(root.join("目录")).unwrap().count(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn incremental_proof_rejects_leaf_and_parent_replacement() {
        let (root, manifest) = fixture();
        let (_, proof) = compare(root.clone(), "目录/a.txt".into(), manifest.clone()).unwrap();
        std::fs::write(root.join("new.txt"), b"same").unwrap();
        // Windows disallows deleting an open file; moving the existing handle is
        // platform dependent, so perform the in-place metadata change there.
        #[cfg(not(windows))]
        std::fs::rename(root.join("new.txt"), root.join("目录/a.txt")).unwrap();
        #[cfg(windows)]
        std::fs::write(root.join("目录/a.txt"), b"different").unwrap();
        assert!(proof.unwrap().make_durable().is_err());
        #[cfg(unix)]
        {
            let (_, proof) = compare(root.clone(), "目录/a.txt".into(), manifest).unwrap();
            std::fs::rename(root.join("目录"), root.join("old")).unwrap();
            std::fs::create_dir(root.join("目录")).unwrap();
            std::fs::write(root.join("目录/a.txt"), b"same").unwrap();
            assert!(proof.unwrap().make_durable().is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn incremental_compare_rejects_links_aliases_and_traversal() {
        let (root, manifest) = fixture();
        std::fs::remove_file(root.join("目录/a.txt")).unwrap();
        std::os::unix::fs::symlink(root.join("outside"), root.join("目录/a.txt")).unwrap();
        assert!(compare(root.clone(), "目录/a.txt".into(), manifest.clone()).is_err());
        assert!(compare(root.clone(), "../a.txt".into(), manifest.clone()).is_err());
        std::fs::remove_file(root.join("目录/a.txt")).unwrap();
        std::fs::write(root.join("目录/A.txt"), b"same").unwrap();
        assert!(compare(root.clone(), "目录/a.txt".into(), manifest.clone()).is_err());
        std::fs::remove_file(root.join("目录/A.txt")).unwrap();
        std::fs::remove_dir(root.join("目录")).unwrap();
        std::os::unix::fs::symlink(root.join("outside"), root.join("目录")).unwrap();
        assert!(compare(root.clone(), "目录/a.txt".into(), manifest).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
