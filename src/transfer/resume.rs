//! 分片位图：记录哪些分片已经收到并通过校验，是断点续传的基础。

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// 分片完成情况位图。第 `i` 位为 1 表示第 `i` 片已校验通过。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkBitmap {
    chunk_count: u32,
    bits: Vec<u8>,
}

impl ChunkBitmap {
    /// 新建空位图（全部未完成）。
    pub fn new(chunk_count: u32) -> Self {
        Self {
            chunk_count,
            bits: vec![0u8; Self::byte_len(chunk_count)],
        }
    }

    /// 位图需要多少字节。
    pub fn byte_len(chunk_count: u32) -> usize {
        chunk_count.div_ceil(8) as usize
    }

    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    pub fn is_set(&self, index: u32) -> bool {
        if index >= self.chunk_count {
            return false;
        }
        let byte = (index / 8) as usize;
        let bit = index % 8;
        self.bits[byte] & (1 << bit) != 0
    }

    /// 标记某片已完成。
    pub fn set(&mut self, index: u32) -> Result<()> {
        self.check_index(index)?;
        let byte = (index / 8) as usize;
        let bit = index % 8;
        self.bits[byte] |= 1 << bit;
        Ok(())
    }

    /// 清除某片的完成标记。
    pub fn clear(&mut self, index: u32) -> Result<()> {
        self.check_index(index)?;
        let byte = (index / 8) as usize;
        let bit = index % 8;
        self.bits[byte] &= !(1 << bit);
        Ok(())
    }

    /// 已完成的片数。
    pub fn count_set(&self) -> u32 {
        self.bits.iter().map(|byte| byte.count_ones()).sum()
    }

    /// 是否全部完成。空文件（0 片）视为已完成。
    pub fn is_complete(&self) -> bool {
        self.count_set() == self.chunk_count
    }

    /// 还缺哪些片，升序。
    pub fn missing(&self) -> Vec<u32> {
        (0..self.chunk_count)
            .filter(|index| !self.is_set(*index))
            .collect()
    }

    /// 已有哪些片，升序。
    pub fn present(&self) -> Vec<u32> {
        (0..self.chunk_count)
            .filter(|index| self.is_set(*index))
            .collect()
    }

    /// 全部标记为已完成。
    pub fn mark_all(&mut self) {
        self.bits.iter_mut().for_each(|byte| *byte = 0xff);
        self.clear_padding_bits();
    }

    /// 由已完成分片列表构造。
    pub fn from_present(chunk_count: u32, present: &[u32]) -> Result<Self> {
        let mut bitmap = Self::new(chunk_count);
        for index in present {
            bitmap.set(*index)?;
        }
        Ok(bitmap)
    }

    /// 合并另一份位图（取并集），用于对端回报续传进度。
    pub fn merge(&mut self, other: &Self) -> Result<()> {
        if self.chunk_count != other.chunk_count {
            return Err(Error::Protocol(format!(
                "位图分片数不一致：本地 {}，对端 {}",
                self.chunk_count, other.chunk_count
            )));
        }
        for (slot, incoming) in self.bits.iter_mut().zip(other.bits.iter()) {
            *slot |= *incoming;
        }
        self.clear_padding_bits();
        Ok(())
    }

    /// 序列化为字节，可直接放进 `Resume` 消息。
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bits.clone()
    }

    /// 由字节还原。
    ///
    /// 长度必须与分片数匹配，且末尾填充位必须为 0——否则同一个状态会有多种
    /// 字节表示，做位图相等比较时会出现假不等。
    pub fn from_bytes(chunk_count: u32, bytes: &[u8]) -> Result<Self> {
        let expected = Self::byte_len(chunk_count);
        if bytes.len() != expected {
            return Err(Error::Protocol(format!(
                "{chunk_count} 片应有 {expected} 字节位图，实际 {} 字节",
                bytes.len()
            )));
        }
        let mut bitmap = Self {
            chunk_count,
            bits: bytes.to_vec(),
        };
        if !bitmap.padding_bits_are_clear() {
            return Err(Error::Protocol("位图末尾填充位不为 0".into()));
        }
        bitmap.clear_padding_bits();
        Ok(bitmap)
    }

    fn check_index(&self, index: u32) -> Result<()> {
        if index >= self.chunk_count {
            return Err(Error::Protocol(format!(
                "分片下标 {index} 越界，共 {} 片",
                self.chunk_count
            )));
        }
        Ok(())
    }

    fn padding_bits_are_clear(&self) -> bool {
        let remainder = self.chunk_count % 8;
        if remainder == 0 || self.bits.is_empty() {
            return true;
        }
        let mask = !((1u8 << remainder) - 1);
        self.bits[self.bits.len() - 1] & mask == 0
    }

    fn clear_padding_bits(&mut self) {
        let remainder = self.chunk_count % 8;
        if remainder == 0 || self.bits.is_empty() {
            return;
        }
        let mask = (1u8 << remainder) - 1;
        let last = self.bits.len() - 1;
        self.bits[last] &= mask;
    }
}

impl std::fmt::Debug for ChunkBitmap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ChunkBitmap({}/{} 已完成)",
            self.count_set(),
            self.chunk_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 新位图全空() {
        let bitmap = ChunkBitmap::new(10);
        assert_eq!(bitmap.count_set(), 0);
        assert!(!bitmap.is_complete());
        assert_eq!(bitmap.missing(), (0..10).collect::<Vec<_>>());
        assert!(bitmap.present().is_empty());
    }

    #[test]
    fn 置位与清位() {
        let mut bitmap = ChunkBitmap::new(10);
        bitmap.set(3).unwrap();
        bitmap.set(9).unwrap();
        assert!(bitmap.is_set(3));
        assert!(bitmap.is_set(9));
        assert!(!bitmap.is_set(4));
        assert_eq!(bitmap.count_set(), 2);
        assert_eq!(bitmap.present(), vec![3, 9]);
        assert_eq!(bitmap.missing(), vec![0, 1, 2, 4, 5, 6, 7, 8]);

        bitmap.clear(3).unwrap();
        assert!(!bitmap.is_set(3));
        assert_eq!(bitmap.present(), vec![9]);
    }

    #[test]
    fn 越界下标报错() {
        let mut bitmap = ChunkBitmap::new(8);
        assert!(bitmap.set(8).is_err());
        assert!(bitmap.clear(8).is_err());
        assert!(bitmap.set(u32::MAX).is_err());
        assert!(!bitmap.is_set(8));
    }

    #[test]
    fn 全部完成后结束() {
        let mut bitmap = ChunkBitmap::new(9);
        bitmap.mark_all();
        assert!(bitmap.is_complete());
        assert_eq!(bitmap.count_set(), 9);
        assert!(bitmap.missing().is_empty());
        assert!(bitmap.padding_bits_are_clear(), "填充位必须清零");
    }

    #[test]
    fn 字节往返() {
        for count in [0u32, 1, 7, 8, 9, 64, 65, 1000] {
            let mut bitmap = ChunkBitmap::new(count);
            if count > 0 {
                bitmap.set(0).unwrap();
                bitmap.set(count - 1).unwrap();
            }
            let bytes = bitmap.to_bytes();
            assert_eq!(bytes.len(), ChunkBitmap::byte_len(count));
            let back = ChunkBitmap::from_bytes(count, &bytes).unwrap();
            assert_eq!(bitmap, back, "{count} 片往返失败");
        }
    }

    #[test]
    fn 字节长度不符报错() {
        assert!(ChunkBitmap::from_bytes(16, &[0u8; 1]).is_err());
        assert!(ChunkBitmap::from_bytes(8, &[0u8; 2]).is_err());
    }

    #[test]
    fn 填充位不为零报错() {
        // 9 片需要 2 字节，第 2 字节只有第 0 位有效，其余必须为 0。
        assert!(ChunkBitmap::from_bytes(9, &[0xff, 0xff]).is_err());
        assert!(ChunkBitmap::from_bytes(9, &[0xff, 0x01]).is_ok());
    }

    #[test]
    fn 合并取并集() {
        let mut a = ChunkBitmap::from_present(8, &[0, 1, 2]).unwrap();
        let b = ChunkBitmap::from_present(8, &[2, 3, 4]).unwrap();
        a.merge(&b).unwrap();
        assert_eq!(a.present(), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn 合并分片数不同报错() {
        let mut a = ChunkBitmap::new(8);
        let b = ChunkBitmap::new(9);
        assert!(a.merge(&b).is_err());
    }

    #[test]
    fn 空位图视为已完成() {
        let bitmap = ChunkBitmap::new(0);
        assert!(bitmap.is_complete());
        assert!(bitmap.to_bytes().is_empty());
        assert_eq!(ChunkBitmap::from_bytes(0, &[]).unwrap(), bitmap);
    }
}
