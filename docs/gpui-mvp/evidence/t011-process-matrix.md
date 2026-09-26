# T011 进程恢复、兼容与故障矩阵

GPUI-0016 / T011 attempt 1；base `c96fc0759123e3fcb24e021ec020e566463b704a`；固定验收 ref `2041a38756b87ba7856dcd343624d98df2283c5a`。最终候选 SHA、完整本地门禁及 exact-head 三平台结果以 Issue #24 的 REPORT/ACCEPTED/MERGED 为准，不预填未来通过。

本地最终代码门禁：fmt、GUI 全库 426、desktop 155（由脚本执行并汇总）、核心库 271+二进制 1、核心/GUI Clippy（-D warnings）、signal/net/transport 专项、GUI check/build 和 CLI build，共 12 项，全部 0 failed / 0 ignored。13 组矩阵 PASS、21 条进程证明；最终候选 head 的脚本与 CLI E2E 另在 REPORT 记录，不提前填 CI。

可复现命令：

```sh
python3 scripts/desktop-e2e.py --output /tmp/desktop-e2e-new-evidence
cargo test --locked --offline --all-targets
cargo build --locked --offline
bash scripts/e2e.sh
```

Windows 使用 `py -3 scripts/desktop-e2e.py --output "$env:TEMP/desktop-e2e-new-evidence"`。macOS 使用 arm64 本机 Python/Rust，先按现有测试说明添加 RFC 5780 fixture 的 lo0 127.0.0.2 alias。目录必须在 checkout 外且为空；失败日志不覆盖。脚本输出 `desktop.log` 与 `matrix.json`，包含命令、平台、架构、SHA、dirty 标记、退出码、命名测试以及进程证明。CLI E2E 仍是原脚本，使用刚构建的 target/debug；共享 target 时先建立临时 target 符号链接、执行后移除，不能测试旧二进制或提交链接。

| 场景 | 本地 Linux 实际证据与证明类型 | 对应测试 |
| --- | --- | --- |
| 未配置/配置恢复 | actor 首次无配置/网络，明确保存后上线；硬杀重开身份、目录、完成记录保持，未自动排队 | `three_process_passive_directory_collision_and_signal_restart`；原 config 原子保存/损坏保留回归 |
| 被动/多 peer | A 未发 Connect，B/C 两个真实进程认证并收发；重启后再次被动接入 | 同上；原三 peer Session 回归 |
| 文件/目录 | 中文/emoji 2 MiB 文件、中文顶层/嵌套/空目录/空文件 5 项，实际内容一致；大文件 70 MiB 完整 BLAKE3/字节比较、双方持久回执 | 三进程测试、pause/kill 测试与原单文件回归 |
| 暂停 | 真实 sender/receiver/同时发起 Pause→两端 Paused/零速率→显式 Continue；同 TaskID、无重复文件 | `two_process_pause_both_sides_and_storage_source_errors_reach_ui`；原最后 chunk/暂停超时边界 |
| 任一端硬杀 | OS SIGKILL；重开同身份/TaskID、Interrupted/零速率/无隐式队列，连接后手动 Continue，完整内容和回执 | `session_process_kill_either_endpoint_restart_requires_manual_continue`；保留原 T006 真实进程强杀 |
| 发布边界硬杀 | 十个持久化边界真实子进程被杀，析构不执行；重开验证旧数据、新数据、唯一备份和回执 | `os_kill_at_every_publication_boundary_preserves_old_new_and_single_receipt` |
| 重名/回执幂等 | 三进程旧内容备份一次、新内容原名；原回执丢失重试、时间戳撞名/外部抢占/双线程发布均保留 | 三进程测试、`lost_completed_frame_replays_receipt_without_republishing`、publish 全模块 |
| 并发/公平 | 原实际 QUIC 队列 1/2/3、降并发不杀任务、阻塞文件隔离；实际 poll_write 短写/借用/迟到任务的 quantum 字节上限 | transfer/queue 原回归；不是物理 Mbps 门槛 |
| 源变化/消失 | 实际暂停后修改内容或删除源；UI Failed、安全诊断、零速率、无假完成 | 双进程 source errors；原 receiver Continue 错误传播 |
| 磁盘满/权限 | StorageFull 与 PermissionDenied 是明确模拟 I/O，经过真实接收与 UI 失败态，修复后同 ID 成功；另有真实 Unix chmod 0500 拒绝与恢复 | 双进程 storage errors、`actual_unix_receive_permission_failure_reaches_ui_and_retry_preserves_old_file`；Windows 真实 occupied-target 回归仍需该 CI 执行 |
| 网络/信令 | 端点实际硬杀使传输 Interrupted；信令服务实际停止/原地址重启，同身份重登记后继续真实文件 | Session kill/三进程；原信令断开仍保留认证直连回归 |
| 安全 | 路径/链接/非法帧/身份不符的原真实模块回归；Linux symlink、Windows junction、Unix staging symlink 按实际 cfg 平台记录 | files/protocol/secure_fs/session 模块，无新增生产测试入口 |
| 兼容/测速 | 原 CLI 全库/E2E 独立；旧 CLI/旧桌面能力明确拒绝；同连接测速/取消/令牌隔离与文件互斥原回归 | protocol/session/transfer 原测试 |

初次 harness 的完整失败日志保留：旧映射 Connected 导致重启打洞超时，修复 Session 候选刷新后通过；初始存储错误预期写成 Interrupted，但实际产品规范是可重试 Failed，改为更精确地检查双方 Failed/诊断，保留旧日志。原测试未删、未 ignore、未缩减断言。首次 Python 插入失败后筛选到了 0 项测试的命令不算通过，后来实际新增映射保持测试并要求真实运行。

发布 ten-boundary 是真实硬杀；旧 errno 注入是模拟，二者不混用。Unix 实际权限和 Windows 被占用文件不是“真实满盘”；未破坏宿主磁盘进行 ENOSPC 实验。CI 平台结果必须来自当前 head；不能用 Linux 结果代填 Windows/macOS。

T012 尚需物理 Win10 22H2/Win11、Apple Silicon、真实中文 IME/Wayland/DPI、Windows↔Linux 双 NAT 和原生 600 秒，以及打包/签名状态。此矩阵不宣称这些已验收。
