# T005 协议验证

任务：GPUI-0009 / T005 attempt 1。基线：`74fadd82ee8f277958fb251708549cc508679b78`。固定验收文档：`2041a38756b87ba7856dcd343624d98df2283c5a`。

本地 Linux x86_64 使用本分支源码和 locked/offline 依赖验证：

| 命令 | 结果 |
| --- | --- |
| `./scripts/e2e.sh`（先构建当前 CLI） | PASS：真实进程 loopback 打洞、隧道、测速、2 MB 文件 SHA256、重连 |
| `cargo fmt --all -- --check` | PASS |
| `cargo test --locked --offline --all-targets` | 270 library + 1 integration，0 failed/ignored |
| `cargo clippy --locked --offline --all-targets -- -D warnings` | PASS |
| `cargo test --locked --offline --features gui --lib` | 335 passed，0 failed/ignored |
| `cargo test --locked --offline --features gui --lib desktop::` | 65 passed |
| `cargo test --locked --offline --features gui --lib discovery::signal` | PASS |
| `cargo test --locked --offline --features gui --lib net::` | PASS |
| `cargo test --locked --offline --features gui --lib transport::` | PASS |
| `cargo check --locked --offline --features gui --bin p2p-desktop` | PASS |
| `cargo build --locked --offline --features gui --bin p2p-desktop` | PASS |
| `cargo clippy --locked --offline --all-targets --features gui -- -D warnings` | PASS |

新增 11 项协议测试和 1 项真实 loopback QUIC 兼容测试；原会话测试也走新增能力协商。黄金字节验证桌面 Hello/Ready/ResumeTask 与已有 CLI 核心判别值。恶意边界覆盖分配前帧长度拒绝、manifest 自洽但非法参数、路径穿越和跨平台名称、尾随数据、位图空余位、任务容量、错身份、乱序/重复请求、未知恢复、同时暂停、完成竞态、测速授权及令牌重放。

协议模块的部分接口供 T006–T009 接入，当前没有文件传输或测速业务接线。未声称磁盘恢复、目录发布或完整产品行为已通过。当前头的 GitHub Actions 链接、独立 diff 复核和合并证据记录于 Issue #24 对应 REPORT/ACCEPTED/MERGED 事件。Windows/macOS CI 不代表真实最低系统或人工交互验收；真实双 NAT 尚未执行。
