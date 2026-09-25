# T003 本地验证证据

本文件记录 Linux 本地执行的命令和测试范围。提交后的精确 head、GitHub Actions 运行链接及三平台任务测试数量写入 Issue #24 的 T003 REPORT；本文件不把 Linux 结果表述为 Windows 或 macOS 原生验证。

## 环境

```text
OS: Ubuntu 24.04.5 LTS x86_64
Kernel: Linux 6.8.0-139-generic
rustc 1.98.1 (48a229cea 2026-09-01)
cargo 1.98.1 (797e8a9bc 2026-08-05)
```

## 命令结果

| 命令 | 结果 |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo test --locked --offline --all-targets` | PASS，265 个库测试 + 1 个集成测试 |
| `cargo clippy --locked --offline --all-targets -- -D warnings` | PASS |
| `cargo test --locked --offline --features gui --lib` | PASS，305 个测试 |
| `cargo test --locked --offline --features gui --lib desktop::` | PASS，40 个桌面测试 |
| `cargo check --locked --offline --features gui --bin p2p-desktop` | PASS |
| `cargo build --locked --offline --features gui --bin p2p-desktop` | PASS |
| `cargo clippy --locked --offline --all-targets --features gui -- -D warnings` | PASS |

GPUI 命令有依赖 `proc-macro-error2` 的 future-incompatibility 提示；本地命令均退出码 0。该提示不属于本次任务代码的编译或 Clippy 警告。

## T003 回归覆盖

21 个任务测试覆盖：随机规范 TaskId 与稳定 peer ID；发送/接收本机路径类型；不可变绑定；非法及终态转换；受限诊断；活跃任务启动时转 Interrupted 且不自动重排；Paused 与终态重启保留；新建任务先以 Scanning 持久化；同一数据目录第二写者被拒绝；故障注入发生在替换前时旧快照不变、候选任务不暴露且临时文件清理；截断 JSON、未来 store/schema 版本、符号链接和过宽 Unix 权限诊断时不重写旧文件；sender/receiver 只凭 TaskId 查询既有本机绑定且只接受 Paused、Interrupted、可重试 Failed；Queued、Scanning、Connecting、Negotiating、Transferring、Pausing、Finalizing、Completed 与不可重试 Failed 均被拒绝；两种方向的恢复查询均返回原本机绑定、不接受替代路径且不改变任务状态；暂停任务重启往返保留 ID、peer、路径、manifest、状态、诊断及已显式刷新的进度提示；进度提示在显式 coalesced flush 前保持易失；快照不保存内容字节或任意错误文本；任务事件有界且只含安全域字段。

## 平台边界

本 worker 在 Linux x86_64 上运行本地测试和 GPUI check/build。Windows 与 Apple Silicon macOS 没有原生执行；它们的任务测试、GPUI 编译和 windows-all 结果以精确 head 的 GitHub Actions 为准。CI pending 不视作通过。
