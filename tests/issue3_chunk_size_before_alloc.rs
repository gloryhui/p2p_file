//! Issue #3 回归：发送端的 `chunk_size` 必须在**分配缓冲区之前**校验。
//!
//! `manifest_from_reader` 的第一件事过去是 `vec![0u8; chunk_size as usize]`，
//! 校验却发生在之后的 `FileManifest::new` 里。于是 `--chunk-size 4294967295`
//! 会先真的申请 4 GiB，才轮得到「超出范围」的报错。
//!
//! 这里用独立的集成测试二进制 + 统计分配器直接观察这次调用的分配峰值：
//! 旧代码会看到一次 ≈ chunk_size 的分配，修复后峰值接近 0。

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct TrackingAllocator;

// SAFETY: 只是把调用转发给系统分配器，额外做一次计数。
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let in_use = CURRENT.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(in_use, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

use p2p_file::protocol::manifest::{MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};

/// 比单片上限略大：旧代码会在这里分配 16 MiB + 1 字节。
const ABOVE_MAX: u32 = MAX_CHUNK_SIZE + 1;

fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let baseline = CURRENT.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let value = f();
    let peak = PEAK.load(Ordering::Relaxed);
    (value, peak.saturating_sub(baseline))
}

/// 这个二进制只有一个测试：统计分配器是进程级的，并行测试会互相污染。
#[test]
fn 非法_chunk_size_不会先分配再报错() {
    let mut reader = std::io::Cursor::new(vec![0u8; 1024]);

    // 先确认探针本身有效：合法的 chunk_size 一定会分配一块 ≈ chunk_size 的缓冲。
    let (result, peak) =
        measure(|| p2p_file::transfer::manifest_from_reader("t.bin", MIN_CHUNK_SIZE, &mut reader));
    assert!(result.is_ok(), "合法的 chunk_size 应当正常工作");
    assert!(
        peak >= MIN_CHUNK_SIZE as usize,
        "探针失效：合法路径应当分配至少 {MIN_CHUNK_SIZE} 字节，实际峰值 {peak}"
    );

    // 超过上限：必须在分配之前就失败。
    for bad in [ABOVE_MAX, u32::MAX] {
        let mut reader = std::io::Cursor::new(vec![0u8; 1024]);
        let (result, peak) =
            measure(|| p2p_file::transfer::manifest_from_reader("t.bin", bad, &mut reader));
        let err = result.expect_err("超过单片上限的 chunk_size 必须被拒绝");
        assert!(
            matches!(err, p2p_file::Error::Protocol(_)),
            "chunk_size={bad} 应当是协议错误，实际 {err:?}"
        );
        assert!(
            peak < 1024 * 1024,
            "chunk_size={bad} 在报错前分配了 {peak} 字节，说明校验发生在分配之后"
        );
    }

    // 0 和低于下限的值同样不能进入分配路径。
    for bad in [0u32, 1, MIN_CHUNK_SIZE - 1] {
        let mut reader = std::io::Cursor::new(vec![0u8; 1024]);
        let (result, peak) =
            measure(|| p2p_file::transfer::manifest_from_reader("t.bin", bad, &mut reader));
        assert!(result.is_err(), "chunk_size={bad} 应当被拒绝");
        assert!(peak < 1024 * 1024, "chunk_size={bad} 分配了 {peak} 字节");
    }
}
