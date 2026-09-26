# T006 单文件恢复验证

任务：GPUI-0010 / T006 attempt 1。基线：`e56eca9e5b8d029966c9fd3f7d5b2c729dfa0b59`。固定验收文档：`2041a38756b87ba7856dcd343624d98df2283c5a`。

## 行为证据

- `desktop::transfer_files`：源文件变更、替换、消失与错误 peer；暂停 checkpoint 重开、篡改清位；同内容不同 inode 目标冲突不冒认回执；hard-link 发布后、回执前重开恢复。
- `desktop::transfer`：已认证真实 loopback QUIC 的正向、反向与空文件；sender/receiver/同时暂停后 ID-only Continue；暂停撞最后一片；5 秒暂停确认超时保留下载；切断 Completed 后幂等重放；发布失败不完成且接收方可在冲突消除后继续。
- `session_command_sends_to_passive_peer_using_owned_transfer_service`：长期信令会话建立并协商后，经有界 SendFile 命令到被动 peer 的实际落盘文件校验。
- `queued_old_epoch_store_write_cannot_reactivate_an_interrupted_task`：单阻塞 worker 上确定性排队旧写入与中断，旧 epoch 不得重新激活任务。
- 追加协议帧的 golden tag、方向/索引/大小边界，保留原 CLI discriminant 与回归。

## 真实进程强杀

运行：`cargo test --locked --offline --features gui --lib real_process_kill_of_either -- --nocapture`。

测试启动两个独立 OS 子进程，以持久身份完成 QUIC/Ed25519/channel binding/桌面协商。使用 70 MiB 源文件，在默认策略产生非空 durable bitmap 后设置测试同步门。分别强杀 sender 和 receiver；存活进程正常退出。重开任务库后状态为 Interrupted，重验 bitmap 后已有分片非零且未完成，再启动双方并显式继续同 TaskId。最终完整清单和双方持久回执一致，任务不重复创建。

本地一轮实际输出：

```text
process hard-kill a: resume from 53 durable chunks; 70 MiB manifest and both receipts verified
process hard-kill b: resume from 46 durable chunks; 70 MiB manifest and both receipts verified
```

checkpoint 片数受真实 1 秒/64 MiB 阈值与运行速度影响，不是固定通过门槛。通过条件是实际 kill 非成功退出、重开后的非零安全进度、同身份/TaskId、最终全清单和回执。子进程入口及同步门仅编译进测试；没有生产故障环境变量。该证据没有把 Drop 当作强杀，也没有宣称真实 NAT 或最低系统验证。

## 验证命令

| 命令 | 本地 Linux 结果 |
| --- | --- |
| `./scripts/e2e.sh`（先构建当前 CLI） | PASS：打洞、并发隧道、测速、2 MB 文件 SHA256 和重连 |
| `cargo fmt --all -- --check` | PASS |
| `cargo test --locked --offline --all-targets` | 270 library + 1 integration PASS |
| `cargo clippy --locked --offline --all-targets -- -D warnings` | PASS |
| `cargo test --locked --offline --features gui --lib` | 351 passed，0 failed/ignored |
| `cargo test --locked --offline --features gui --lib desktop::` | 81 passed，0 failed/ignored |
| `cargo test --locked --offline --features gui --lib discovery::signal` | PASS |
| `cargo test --locked --offline --features gui --lib net::` | PASS |
| `cargo test --locked --offline --features gui --lib transport::` | PASS |
| `cargo check --locked --offline --features gui --bin p2p-desktop` | PASS |
| `cargo build --locked --offline --features gui --bin p2p-desktop` | PASS |
| `cargo clippy --locked --offline --all-targets --features gui -- -D warnings` | PASS |

旧 CLI 端到端脚本与三平台 exact-head CI 的实际结果、当前 SHA、PR、独立复核和 merge fence 记录在 Issue #24 的 REPORT/ACCEPTED/MERGED 事件中。保留既有 proc-macro-error2 future-incompatibility 警告。

## 本阶段限制

仅单文件 basename，不包含目录展开、备份旧文件事务、全局队列、测速执行或完整业务 UI。当前默认 chunk 为 256 KiB，最多 65536 个 chunk；源文件和快照还有资源容量约束。Windows/macOS CI 是对应 runner 验证，不等于 Windows 10/11、Apple Silicon 人工交互或两地双 NAT。后续 T007–T012 验收仍需分别完成。
