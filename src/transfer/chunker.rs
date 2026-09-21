//! 分片切分与清单生成。

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::error::{Error, Result};
use crate::protocol::manifest::{
    ChunkHash, DEFAULT_CHUNK_SIZE, FileManifest, MAX_CHUNK_SIZE, validate_chunk_size,
};

/// 边读边算，由一个读取器生成文件清单。
///
/// 不在内存里装下整个文件，所以传大文件时内存占用只跟分片大小有关。
pub fn manifest_from_reader<R: Read>(
    file_name: &str,
    chunk_size: u32,
    reader: &mut R,
) -> Result<FileManifest> {
    // 必须在分配缓冲区之前校验：`chunk_size` 直接来自用户/CLI，写成 4 GiB
    // 会让下面这一行真的去申请 4 GiB，在 `FileManifest::new` 有机会报错之前
    // 就把进程打爆。
    validate_chunk_size(chunk_size)?;

    let mut buffer = vec![0u8; chunk_size as usize];
    let mut chunks: Vec<ChunkHash> = Vec::new();
    let mut total_len: u64 = 0;

    loop {
        let filled = read_full(reader, &mut buffer)?;
        if filled == 0 {
            break;
        }
        chunks.push(ChunkHash::of(&buffer[..filled]));
        total_len += filled as u64;
        if filled < buffer.len() {
            // 读不满说明已到文件末尾。
            break;
        }
    }

    FileManifest::new(file_name.to_string(), total_len, chunk_size, chunks)
}

/// 由文件路径生成清单。
pub fn manifest_from_path(path: &Path, chunk_size: u32) -> Result<FileManifest> {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download.bin".to_string());

    // 用 BufReader 减少小分片场景下的系统调用。
    let mut reader = std::io::BufReader::with_capacity(1 << 20, File::open(path)?);
    manifest_from_reader(&file_name, chunk_size, &mut reader)
}

/// 默认分片大小下的清单。
pub fn manifest_from_path_default(path: &Path) -> Result<FileManifest> {
    manifest_from_path(path, DEFAULT_CHUNK_SIZE)
}

/// 从文件里读出指定分片的数据。发送端每个分片调用一次。
pub fn read_chunk(file: &mut File, offset: u64, len: u32) -> Result<Vec<u8>> {
    use std::io::{Seek, SeekFrom};

    // `len` 通常来自已校验的清单，但这里是「按长度分配」的地方，再挡一道：
    // 不允许任何调用方用它申请超过单片上限的缓冲。
    if len > MAX_CHUNK_SIZE {
        return Err(Error::Protocol(format!(
            "请求的分片长度 {len} 超过单片上限 {MAX_CHUNK_SIZE}"
        )));
    }

    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; len as usize];
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// 反复读直到填满缓冲区或遇到 EOF，返回实际读到的字节数。
fn read_full<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::manifest::MIN_CHUNK_SIZE;

    fn run(data: &[u8], chunk_size: u32) -> FileManifest {
        let mut cursor = std::io::Cursor::new(data.to_vec());
        manifest_from_reader("t.bin", chunk_size, &mut cursor).unwrap()
    }

    #[test]
    fn 每片都能校验() {
        let data: Vec<u8> = (0..MIN_CHUNK_SIZE * 3 + 17)
            .map(|i| (i % 256) as u8)
            .collect();
        let manifest = run(&data, MIN_CHUNK_SIZE);

        assert_eq!(manifest.total_len, data.len() as u64);
        assert_eq!(manifest.chunk_count(), 4);
        assert!(manifest.verify_root_hash());

        for index in 0..manifest.chunk_count() {
            let (offset, len) = manifest.chunk_range(index).unwrap();
            assert!(manifest.verify_chunk(
                index,
                &data[offset as usize..(offset + u64::from(len)) as usize]
            ));
        }
    }

    #[test]
    fn 整片边界() {
        let size = MIN_CHUNK_SIZE;
        let data = vec![9u8; size as usize * 2];
        let manifest = run(&data, size);
        assert_eq!(manifest.chunk_count(), 2, "刚好整除不应多出一片空片");
        assert_eq!(manifest.chunk_len(1), Some(size));
    }

    #[test]
    fn 空文件没有分片() {
        let manifest = run(&[], MIN_CHUNK_SIZE);
        assert_eq!(manifest.total_len, 0);
        assert_eq!(manifest.chunk_count(), 0);
        assert!(manifest.verify_root_hash());
    }

    #[test]
    fn 单字节文件() {
        let manifest = run(&[0x42], MIN_CHUNK_SIZE);
        assert_eq!(manifest.chunk_count(), 1);
        assert_eq!(manifest.chunk_len(0), Some(1));
        assert!(manifest.verify_chunk(0, &[0x42]));
    }

    #[test]
    fn 清单读到实际字节数() {
        // 声称比实际大得多的读取器（模拟设备文件）不应把它读穿的字节算进去。
        let data = vec![1u8; MIN_CHUNK_SIZE as usize + 5];
        let manifest = run(&data, MIN_CHUNK_SIZE);
        assert_eq!(manifest.total_len, MIN_CHUNK_SIZE as u64 + 5);
    }

    #[test]
    fn 路径生成清单() {
        let dir = std::env::temp_dir().join(format!("p2p_file_chunk_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hello.txt");
        let content = b"hello p2p file transfer";
        std::fs::write(&path, content).unwrap();

        let manifest = manifest_from_path(&path, MIN_CHUNK_SIZE).unwrap();
        assert_eq!(manifest.file_name, "hello.txt");
        assert_eq!(manifest.total_len, content.len() as u64);
        assert!(manifest.verify_chunk(0, content));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn 读分片与清单一致() {
        let dir = std::env::temp_dir().join(format!("p2p_file_read_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("data.bin");
        let content: Vec<u8> = (0..MIN_CHUNK_SIZE * 2 + 3)
            .map(|i| (i % 253) as u8)
            .collect();
        std::fs::write(&path, &content).unwrap();

        let manifest = manifest_from_path(&path, MIN_CHUNK_SIZE).unwrap();
        let mut file = File::open(&path).unwrap();
        for index in 0..manifest.chunk_count() {
            let (offset, len) = manifest.chunk_range(index).unwrap();
            let data = read_chunk(&mut file, offset, len).unwrap();
            assert!(
                manifest.verify_chunk(index, &data),
                "第 {index} 片读出来对不上"
            );
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Issue #3：`chunk_size` 必须在分配缓冲区**之前**被拒绝。
    ///
    /// 旧代码先 `vec![0u8; chunk_size as usize]` 再交给 `FileManifest::new`
    /// 检查，所以 `--chunk-size 4294967295` 会真的去申请 4 GiB。
    #[test]
    fn 非法分片大小在分配缓冲区之前被拒绝() {
        use crate::error::Error;
        use crate::protocol::manifest::{MAX_CHUNK_SIZE, validate_chunk_size};

        for bad in [0u32, 1, MIN_CHUNK_SIZE - 1, MAX_CHUNK_SIZE + 1, u32::MAX] {
            let mut cursor = std::io::Cursor::new(vec![0xabu8; 128]);
            let err = manifest_from_reader("t.bin", bad, &mut cursor).unwrap_err();
            assert!(
                matches!(err, Error::Protocol(_)),
                "chunk_size={bad} 应返回协议错误，实际 {err:?}"
            );
            // 同一个判断也单独暴露出来给 CLI / 其它调用方复用。
            assert!(validate_chunk_size(bad).is_err());
        }

        // 合法值照常工作，边界值也算合法。
        for good in [MIN_CHUNK_SIZE, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE] {
            let mut cursor = std::io::Cursor::new(vec![0xabu8; 128]);
            let manifest = manifest_from_reader("t.bin", good, &mut cursor).unwrap();
            assert_eq!(manifest.total_len, 128);
            assert_eq!(manifest.chunk_size, good);
        }
    }

    /// `read_chunk` 是「按长度分配」的地方，超过单片上限必须直接拒绝。
    #[test]
    fn 读取超过单片上限的长度会被拒绝() {
        use crate::error::Error;
        use crate::protocol::manifest::MAX_CHUNK_SIZE;

        let dir = std::env::temp_dir().join(format!("p2p_file_readlimit_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("small.bin");
        std::fs::write(&path, b"hello").unwrap();
        let mut file = File::open(&path).unwrap();

        let err = read_chunk(&mut file, 0, MAX_CHUNK_SIZE + 1).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "实际 {err:?}");
        // u32::MAX 也不能触发大分配。
        assert!(read_chunk(&mut file, 0, u32::MAX).is_err());

        // 正常长度仍然能读。
        assert_eq!(read_chunk(&mut file, 0, 5).unwrap(), b"hello");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
