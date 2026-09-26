# T007 目录与发布事务验证

任务 GPUI-0011 / T007 attempt 1；base `c8073e64ed868e3a9e47acf592fb8484cb10fafd`；固定规格 `2041a38756b87ba7856dcd343624d98df2283c5a`。最终 head、PR、exact-head 平台日志与合并结果记录在 Issue #24 对应 REPORT/ACCEPTED/MERGED 中。

## 本地 Linux 检查

| 命令 | 结果 |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo test --locked --offline --features gui --lib` | 375 PASS，0 failed/ignored |
| `cargo test --locked --offline --features gui --lib desktop::` | 105 PASS，0 failed/ignored |
| `cargo test --locked --offline --all-targets` | 270 library + 1 integration PASS |
| `cargo clippy --locked --offline --all-targets -- -D warnings` | PASS |
| GUI signal / net / transport 专项 | PASS |
| `cargo check --locked --offline --features gui --bin p2p-desktop` | PASS |
| `cargo build --locked --offline --features gui --bin p2p-desktop` | PASS |
| `cargo clippy --locked --offline --all-targets --features gui -- -D warnings` | PASS |
| `cargo build --locked --offline` 后 `./scripts/e2e.sh` | PASS：打洞、并发隧道、测速、2 MB SHA256 与重连；实际输出见 Issue #24 REPORT |

## 可审计行为

- `authenticated_directory_preserves_structure_empty_entries_and_collision_backups`：实际认证 QUIC，保留所选顶层、嵌套/中文/空目录/空文件；旧内容按时间戳备份；记录 group 一致，Completed 重试不增任务或备份。
- `directory_group_keeps_original_receive_root_after_settings_change`：创建顶层后修改设置，后续子文件仍落在已绑定根目录。
- `every_publication_boundary_reopens_without_losing_old_data_or_duplicate_backup`：before-prepared、after-prepared、before-backup、after-backup-filesystem、after-backup-journal、before-publish、after-publish-filesystem、after-publish-journal、before-receipt、after-receipt。每点注入 StorageFull 错误并关闭/重开 store 和 download；验证旧文件/备份存在、未持久回执不假完成、恢复后正确新内容与唯一旧备份。回执后故障保留已完成状态。
- 实际两线程同目标竞争，共享单 writer 发布序列：两个任务都有合法回执，原内容与被后一个任务替换的新内容均保留。
- 同毫秒备份名已有占用时原子 no-replace + 固定 -1 后缀，占用文件不改变。
- 外部进程在备份后抢占正式名、回执前替换正式文件：不覆盖抢占者、不提交假回执，旧备份和新 staging 保留；冲突清除后恢复不重复备份。
- PermissionDenied 故障注入、损坏 journal 绑定、原子 no-replace 目标占用，均保留可恢复信息。
- 根以下 symlink 和原路径替换链接不被跟随；staging .part/.bitmap 链接不触碰未选择文件；NFC/大小写别名明确拒绝。最大合法 basename 使用固定 staging 内部名成功发布并清理 data.part；新增清理断言先复现失败，再修复通过。回执重发会重试此前清理。
- 扫描取消、读取中取消、4096 条目上限、非法 ADS/设备名/UNC/穿越/内部命名空间、扫描失败不产生部分组。
- 原 T006 双端/同时暂停、最后一片竞态、5 秒暂停超时、真实 sender/receiver OS 强杀后 70 MiB 续传、丢完成帧回执重放继续通过。

Windows 额外测试为 `windows_open_target_failure_keeps_old_file_and_can_retry_after_release` 和 `windows_source_junction_and_receive_reparse_directory_are_rejected`；是否执行通过，以最终 exact-head Windows job 日志为准。Linux/macOS/Windows 各平台 cfg 的测试数不同，不用 Linux 数量冒充全部平台结果。

## 证据边界

注入故障后重开证明发布状态机，不把它称作真实掉电。继承的强杀测试是真实 OS 子进程 kill，但仍是 loopback。Windows/macOS hosted CI 不等于 Win10/11 或 Apple Silicon 原生交互；双 NAT 未验证。Windows 无可移植目录 fsync；文件系统需支持同卷 hard link 和原子 no-replace 备份，不支持时保留任务/旧备份/新 staging 并报错。

T007 实现目录与事务，T008 队列公平、T009 测速、T010 完整 UI 和 T011/T012 验收继续独立推进。用户授权的成本控制已接入 PR-only + workflow_dispatch 工作流，保留所有门禁测试命令；中间本地迭代未触发 Actions。
