# T004 / GPUI-0008 本地验证

基线：`6fa57d5d59c24db3a589a716743c720ae60df06b`。规格：`2041a38756b87ba7856dcd343624d98df2283c5a`。
环境：Linux x86_64，Rust 1.98.1。结果针对本文件同提交的源代码；exact-head 三平台 Actions 与独立复核记录见 Issue #24 REPORT/REVIEW/ACCEPTED。

## 必需检查

| 命令 | 结果 |
| --- | --- |
| `cargo fmt --all -- --check` | PASS (exit 0) |
| `cargo test --locked --offline --features gui --lib` | PASS (exit 0) |
| `cargo test --locked --offline --features gui --lib` | PASS (exit 0) |
| `cargo test --locked --offline --all-targets` | PASS (exit 0) |
| `cargo clippy --locked --offline --all-targets -- -D warnings` | PASS (exit 0) |
| `cargo test --locked --offline --features gui --lib desktop::` | PASS (exit 0) |
| `cargo test --locked --offline --features gui --lib discovery::signal` | PASS (exit 0) |
| `cargo test --locked --offline --features gui --lib net::` | PASS (exit 0) |
| `cargo test --locked --offline --features gui --lib transport::` | PASS (exit 0) |
| `cargo check --locked --offline --features gui --bin p2p-desktop` | PASS (exit 0) |
| `cargo build --locked --offline --features gui --bin p2p-desktop` | PASS (exit 0) |
| `cargo clippy --locked --offline --all-targets --features gui -- -D warnings` | PASS (exit 0) |
| `cargo build --locked --offline` | PASS (exit 0) |
| `./scripts/e2e.sh`（先构建本次 CLI） | PASS (exit 0) |

最终源代码连续三轮完整 GUI library 并行测试均 323 passed / 0 failed / 0 ignored，测试运行耗时依次为 2.93s、2.90s、2.88s。默认核心套件 270 passed，另有独立集成测试 1 passed。

CLI E2E 覆盖被动 serve、隧道回显及并发连接、内存测速不落盘、活跃连接跨越重新打洞宽限期、2,000,000 字节文件 SHA256 一致、候选回退、断开后第二次连接。仅用于已有 CLI 兼容回归；GUI 未暴露 tunnel。

## 竞态证据

旧 attempt 迁入后未修改的完整 GUI suite：316 passed / 1 failed；`passive_peer_uses_same_registration_and_third_peer_progresses` 在原 20s 截止时间失败。原测试和断言均保留。

新增 `late_probe_registration_receives_reply_at_validated_actual_source` 确定性丢弃首包，模拟 token 晚注册：临时撤去已验证来源回应的故障注入版本 exit 101 / timeout 2.00s；恢复修复后 exit 0 / PASS。未将故障注入保留在源代码中。

其它新增/加强回归：三 peer 被动接入、同时重复连接保留同一 connection、信令服务停止后仍能通过已认证 QUIC 实际发送数据、同一身份重新注册、配置变化取消卡住的旧注册并释放 TCP、满 UI 队列时终止并 join runtime、离线等待有界与迟到终态回调、错误身份拒绝、单 UDP owner 同 socket、错误 token/截断包、GRO 保留 QUIC 数据和空 UDP、歧义来源和 route 生命周期。

## 未证明项

- Loopback 与 CI 不能证明真实双 NAT。
- 尚无 Windows 10/11 真机、Apple Silicon 交互或本任务人工 UI 验收证据。
- 三平台 CI 的最终运行链接以本 PR exact head 的 Issue #24 审计为准，不能用此本地记录代替。
- `proc-macro-error2 2.0.1` 有现存 future-incompatibility 提示；不是本项目 Clippy 错误，不改变通过标准。
