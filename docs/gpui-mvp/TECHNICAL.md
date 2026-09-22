# 技术设计与实现契约

规格 1.0。此文是实现约束，不代表下面的模块或 API 已存在。公共类型名称可经控制 Agent 调整，语义和验收不能省略。

## 1. 基线事实与复用边界

基线 `312d4665a6688e66f0b1de790e27b65ce59b7834`，Rust edition 2024。

| 现有位置 | 已有能力 | 桌面缺口/必须保留的行为 |
| --- | --- | --- |
| src/identity.rs | 持久 Ed25519、16 字节 NodeId、32 位 hex、密钥防覆盖 | GUI 用平台目录；不能每次启动生成新 ID；CLI 现有路径兼容 |
| src/discovery/signal.rs | 注册签名、心跳、Lookup、PeerCandidates | 目前 lookup/wait 按指定 peer 等待并忽略其它消息；桌面必须支持被动 offer，单 reader 分发 |
| src/net/mod.rs | STUN、同 socket 打洞、QUIC、对端身份核对 | establish 要先指定 peer；需要持久在线、接入任意发起者的桌面服务 |
| src/transport/handshake.rs | TLS exporter 绑定的 Ed25519 握手 | 无接收批准仍不能绕过此认证 |
| src/tunnel/mod.rs | 已认证会话多流业务分发、资源上限 | 复用安全边界；GUI 不开放 TCP tunnel 业务 |
| src/transfer/receiver.rs | 拉取窗口、重复分片拒绝、finalize 后 Complete | 暂停不能调用 discard；进度/取消可观察，现有 CLI 入口保留 |
| src/transfer/sender.rs | manifest、按需回片、完成确认 | 当前一次性调用；需要任务 ID、事件、继续、调度接口 |
| src/storage/mod.rs | written/durable、64 MiB 或 1 秒 checkpoint、恢复重验 | 固定目录结构、新旧文件发布策略、任务回执、暂停 checkpoint |
| src/speedtest.rs | 同连接内存测速、两方向、接收方结果 | 当前默认 10 秒、最大 300 秒；GUI 默认 30 秒，最大需支持 600 秒 |
| .github/workflows/windows.yml | Windows 全部核心测试 | 不是 GPUI 三平台构建，更不是 Win10 兼容证明 |

不要将 docs/ARCHITECTURE.md 中“未来 relay/IPv6”等设计描述当作现成能力。GUI 必须真实展示当前连通性限制。

## 2. 建议模块划分

```text
src/bin/desktop.rs             独立 GPUI 入口，保留原 CLI
src/desktop/mod.rs             AppService / runtime 生命周期、命令事件
src/desktop/config.rs          配置、平台目录、固定身份位置
src/desktop/model.rs           持久任务、运行态、错误与事件类型
src/desktop/store.rs           单写者、原子持久化、版本迁移、单实例锁
src/desktop/session.rs         信令上线、被动接入、连接注册与能力协商
src/desktop/protocol.rs        桌面子协议、任务及目录元数据
src/desktop/queue.rs           队列、并发槽、等权调度、速率采样
src/desktop/files.rs           清单扫描、路径验证与源文件身份
src/desktop/publish.rs         重名备份、发布 journal、恢复和回执
src/desktop/ui/                GPUI 页面及视图模型
tests/desktop_*               无界面领域与环回/进程测试
docs/gpui-mvp/                 规格、流水线及后续 ADR/验收记录
```

目录可按实际代码调整，但 UI、异步业务、持久化和协议不能堆在一个 render() 中。
GUI 通过 feature（建议 gui）或独立 workspace crate 引入；最终选择由 T001 ADR 固定。
默认核心/CLI 构建不能要求安装图形开发包。不得在 std::sync 锁内 await。

### 2.1 GPUI 与线程

- GPUI 主线程只管理视图、焦点、输入、轻量命令和事件；网络在独立 Tokio runtime。
- 目录扫描、全文件哈希、恢复校验和阻塞文件操作不能在 UI render/update 中执行。
- 可用受限 blocking worker 执行 GUI 必需的磁盘工作；这不授权实现 #21 的 1 GiB 队列。
- 命令与事件通道有界，进度事件合并为每任务 4—10 Hz；完成/错误等终态不能被进度淹没。
- Runtime 随程序生命周期创建一次，不在每个按钮中创建；退出要取消任务并有界等待。
- 文件选择器、剪贴板、中文 IME、DPI 由真实 GPUI/平台 API 实现。
- GPUI 和组件库版本必须锁定 Cargo.lock；T001 以官方文档和实际编译确认兼容组合，不沿用未验证版本猜测。

### 2.2 命令/事件建议

命令：SaveSettings、ConnectPeer、AddFiles、AddDirectory、PauseTask、ResumeTask、
SetConcurrency、StartSpeedtest、CancelSpeedtest、Shutdown。

事件：SignalStateChanged、PeerStateChanged、TaskAdded、TaskStateChanged、TaskProgress、
SpeedtestProgress、SpeedtestFinished、RecoverableError。

每个异步响应带 request_id / task_id / connection_generation。旧请求的迟到结果不能覆盖新连接或新任务状态。
磁盘操作失败必须返回事件；不能日志里报错但 UI 仍显示保存成功。

## 3. 配置、身份、单实例和任务存储

### 3.1 路径

用平台 API 获取配置/数据目录及系统 Downloads（包括本地化名称和重定位）：
- Windows 使用 Known Folders；
- macOS 使用系统用户目录；
- Linux 尊重 XDG_CONFIG_HOME / XDG_DATA_HOME 与 xdg-user-dirs。

查不到 Downloads 时提示选择目录，不猜“~/下载”、不退回进程工作目录。
身份密钥与任务状态分开，不上传私钥、不放 repo、不在日志输出。
GUI 若导入已有 CLI 身份，必须显式路径及安全检查；默认位置一经建立固定。
一个数据目录只允许一个应用实例持有写锁；不同测试实例必须使用独立数据目录。

### 3.2 配置字段建议

```json
{
  "schema_version": 1,
  "signal": {"host": "192.0.2.1", "port": 7000},
  "receive_directory": "platform-local-path",
  "send_concurrency": 1,
  "speedtest_seconds": 30,
  "speedtest_direction": "upload"
}
```

示例 IP 为文档地址，不可作为产品默认服务器。
允许合法 IP 或可解析主机名，端口 1—65535；拒绝路径、URL schema、空白和零端口。
配置保存先验证再原子提交；网络连接失败不代表合法配置不能保留。
无配置和配置损坏要区分：损坏时保留原文件并提示，不能静默覆盖。
非 UTF-8 本地源路径要有明确编码策略或入队前拒绝；不能 lossy 转换后悄悄选错文件。

### 3.3 TaskRecord 最小语义

| 字段 | 意义 |
| --- | --- |
| schema_version | 持久格式版本 |
| task_id / group_id | 随机稳定 ID，目录分组可选 |
| peer_id / direction | 绑定经过认证的对端、发送或接收 |
| source_path | 仅发送端本地使用，绝不发上网 |
| receive_root | 仅接收端本地使用，建任务时固定 |
| relative_path / entry_kind | 对端可见的所选相对路径、文件/目录 |
| manifest_identity | 根哈希、长度、chunk 参数，续传必须匹配 |
| state / error_code | 持久任务状态与最近错误 |
| created_at / updated_at | UTC 时间 |
| publish_journal_id / receipt | 发布恢复与完成去重 |
| progress_hint | 仅显示提示，不能代替重读 .bitmap 和哈希验证 |

task_id 必须与 peer_id 组合定位，防止其它节点猜 ID 接管任务。
接收端 .part/.bitmap 按受控任务 ID 命名，隔离同名文件不同任务；禁止把网络路径直接当状态文件路径。
新任务必须持久入队后才允许发第一片；任务数据库采用单写者。
选择 SQLite 事务或原子快照+日志均可，T003 ADR 必须说明 Windows 替换、fsync 和恢复策略。不能普通 fs::write 覆盖唯一 JSON。
UI 高频进度可内存采样，不要求每片写任务数据库；状态转移、身份与最终回执必须可靠提交。
任务存储自身故障时停止启动新任务，明确报错，不能悄悄继续无记录发送。

## 4. 任务状态机

```text
Scanning → Queued → Connecting → Negotiating → Transferring
                                          ├→ Pausing → Paused
                                          ├→ Finalizing → Completed
                                          └→ Interrupted / Failed
Paused / Interrupted / 可恢复 Failed --用户继续--> Queued
启动恢复：所有非终态活动任务 → Interrupted；Paused 保持 Paused
```

- Scanning 的中断可重新扫描，但已持久化子任务不能重复插入。
- Pausing 不是 Paused。先停止补充请求，排空/有界处理在途片，receiver force checkpoint，再持久暂停并确认。
- 暂停超时保留已有 durable 状态，转 Interrupted；不能删除临时文件。
- 双方同时暂停需幂等；暂停撞上完成时，以已持久化发布回执为准，不能把完成退回活动态。
- 接收端 Continue 发 ResumeTask(task_id)；发送端只能恢复自己保存的该 peer 任务，不接受远端 path 参数。
- 重启后 Continue 先连接和能力协商，重新从 receiver bitmap 重验得到缺片；sender UI 旧进度没有权威性。
- receipt 已存在则重发 Complete，不再备份/重传/重发布。
- 完成事件只在最终发布与回执持久化后产生。
- 路径冲突、磁盘满、文件占用、权限错误均保留恢复信息；不能被统一变成 discard。
- 用户正常退出可以请求 checkpoint，但设计不能依赖 Drop 或退出 hook 才能续传。

## 5. 网络与长期在线

### 5.1 生命周期

启动 → 读取配置/身份 → 准备 UDP/候选 → 信令注册 → 在线监听。
用户 ConnectPeer → Lookup → 双方获取同 token 的候选 → 同 socket 打洞 →
QUIC → Ed25519/channel-binding → 核对目标 ID → 桌面能力协商 → Connected。

网络状态至少区分：Unconfigured、ConnectingSignal、SignalOnline、ReconnectingSignal、
PeerPending、Punching、Authenticating、Connected、Disconnected、Failed。
信令掉线时已有 P2P 通道可以继续；不要因信令不可用立即删除任务或关闭有效文件流。
重连退避有抖动和上限（建议 1/2/4…30 秒），不能忙循环；配置变化取消旧代运行。

### 5.2 被动接入与多 peer

现有 CLI serve 需要预指定 peer，而 GUI 接收端不能要求先输入发送方 ID。
需要客户端单独的事件分发器，消费 PeerCandidates、Pending、Pong 和断线：
- 单个连接只有一个读者，不让多个 lookup()/wait_for_peer() 互相吞消息。
- 主动查询与被动 offer 都能发起打洞；同 peer 多次 offer 去重。
- 同一 identity 不为每个任务重新注册，避免服务器踢掉前一连接。
- 同一 peer 的文件与测速复用连接；连接 registry 有 generation 和资源上限。
- 双方同时 Connect 要有确定性的连接去重规则（例如 ID 排序决定保留哪条），且不会关闭正在使用的唯一连接。
- 监听不能在一条长传输期间停止消费新的信令和连接请求。
- 不把任何匿名 QUIC 建连当可信业务，握手有并发和超时上限。
- GUI 分发器不提供 TunnelOpen 的通用远端转发能力。

### 5.3 UDP 所有权

STUN、打洞、QUIC 必须复用正确端口/映射。不得让两个异步 recv 循环竞争同一 UDP socket。
T004 必须用 ADR 和测试说明：
- 在长期 QUIC endpoint 存在时，如何接收/分发新的打洞包；
- 探测包 token 验证、真实源地址和候选地址的处理；
- 如需 UDP adapter，QUIC datagram 不得被自定义 recv 吞掉；
- 不能仅 clone socket 发几个包就宣称完成旧版同等的打洞确认；
- 闲置重建、信令重连和活跃文件传输如何互不破坏。

允许最小必要重构 net/discovery/tunnel；不做中继或全新 NAT 算法。真实双 NAT 验证放在 T011/T012。

## 6. 桌面协议扩展

保留 CLI wire 行为，桌面增加带版本/能力的业务入口。T005 必须明确兼容旧端的错误行为。
如果修改现有 enum，必须保持已发布 discriminant，追加变体并增加 golden 编解码测试。
不兼容变更不能只改文档：需要明确版本协商/升级及旧节点拒绝测试。

建议语义（名称可调整）：
- DesktopHello(version, capabilities) / DesktopReady。
- Offer(task_id, entry_kind, relative_path, manifest_identity/manifest)。
- Resume(task_id, verified_bitmap)；请求/数据继续复用 chunk 基础。
- Pause(task_id, request_id) / Paused(task_id)。
- ResumeTask(task_id) / TaskUnavailable。
- Completed(task_id, root_hash, receipt_version)。
- Error(task_id, typed_code, safe_message)。

路径和 task_id 只表示发送方已选择的任务，不是远端文件系统操作能力。
所有帧/路径/条目数/单任务大小/并发请求都有上限，先验证再分配或创建目录。
manifest 沿用 validate；相对路径不能仅用 safe_file_name 平铺后丢掉目录结构。
空目录使用明确目录条目，不伪造一个零字节文件。
同一连接不同 task_id 的消息不得串用，一条文件流绑定一个任务，控制流有 request_id。
测速数据流的归属必须在 T005/T009 定义，不能多个 handler 同时 accept_uni 抢流。

## 7. 路径与目录安全

线上的路径统一 '/' 分隔、UTF-8 相对路径；本地转换逐组件处理。
拒绝：绝对路径、'..'、'.' 歧义组件、空组件、盘符/UNC、反斜杠注入、NUL、
Windows ADS 冒号、保留设备名、尾随点/空格、过长路径/组件。
第一版不能表示的文件名入队前报错，不能静默替换或截断后碰撞。
大小写折叠或 Unicode 规范化碰撞必须在接收目标平台检测，不覆盖已有条目。

接收根目录以下禁止跟随 symlink/junction/reparse point。单纯 canonicalize 后再 open 不能消除 TOCTOU：
实现需目录句柄相对操作/平台 no-follow、或在明确威胁模型下实现可验证的等价防护并经控制复核。
不接受“可信设备所以不检查网络路径”作为理由。
选中的源目录不追踪特殊文件/链接；扫描数量、内存和取消检查有界。
发送文件源路径仅存在本机任务记录；manifest/错误消息里不得夹带绝对源路径或接收目录。
接收端任务 UI 可以显示本机输出路径，发送端只显示相对路径。

## 8. 数据一致性与重名发布

### 8.1 维持 #20 的约束

每片：校验 → write_all → written bitmap → dirty_bytes → checkpoint_if_due。
checkpoint：sync_data → snapshot → 持久化 bitmap → durable 更新 → dirty 清零 → 时间更新。
默认 64 MiB 或 1 秒，暂停和 finalize 强制 checkpoint。
finalize 保留 sync_all 和目录同步；不因 GUI 有任务 DB 就省略 bitmap 校验。
bitmap 丢失可能导致全量重传（尤其现有 Windows 删除/改名窗口），但不能假完成。
“掉电恢复”允许退回最近安全 checkpoint，不保证一字节不重传。

### 8.2 GUI 独立发布策略

原 CLI 遇重名给新文件加编号，应保持兼容。GUI 采用“备份旧文件，再发布新文件”，不能全局悄悄改 CLI 语义。

备份名规范初始建议：report+20260923T081530123Z.pdf；无后缀则 notes+时间戳。
UTC 毫秒，时间回拨或同毫秒碰撞追加 -1/-2，采用原子 no-replace，不靠 exists()+rename 覆盖。
顶层目录已存在则合并结构，仅冲突的普通文件备份；文件/目录类型冲突报错。
接收未完成时旧文件保持原名可用；不在收第一片时就备份。

### 8.3 发布事务最小状态

同一目标路径的发布必须串行锁定。任务身份固定备份名，不能每次重试生成新时间戳。

```text
PREPARED（新数据完整且已 sync_all，记录目标/备份/内容身份）
  → OLD_BACKED_UP（如旧文件存在，安全改名并持久化目录）
  → NEW_PUBLISHED（no-replace 发布已校验新文件，sync 目录）
  → RECEIPT_COMMITTED（task_id + peer_id + 根哈希 + 完成状态已持久化）
  → 清理 .part/.bitmap/journal 的可清理内容 → Complete
```

每一步前后崩溃都要能通过日志和实际文件身份判定，而不是只相信内存：
- 备份已完成但 journal 未更新：识别指定备份，不重复挪文件。
- 新文件已发布但回执未保存：校验正式文件并补提交回执，不能再备份这份新文件。
- 已有回执但 Complete 丢失：按同任务重发成功回执，避免重复传输。
- 发布失败：不发送 Complete，保留旧备份和新 .part。
- 正式路径被其它进程抢占：不覆盖抢占者，返回冲突等待处理。
- 无旧文件也必须有任务回执；仅凭“目标已存在”不能推断当前任务完成。
- 磁盘满、只读、Windows 文件占用要覆盖；错误回滚不能删除用户旧文件。

该逻辑必须作为可独立测试的状态机完成。不存在一种“跨多个文件 rename 自动原子”的假设。
Windows/Unix directory sync 能力差异需文档化，不能承诺硬件掉电绝对一致；保持保守重验和不假完成。

## 9. 队列、并发、公平和实时速度

- 发送 FIFO 默认 1；允许 1—3，拒绝其它值。目录展开后文件独立排队，空目录不占大数据槽。
- 从 3 改 1：已活动的任务可完成/暂停，不强杀；不再补位，最终降到新上限；UI 表明正在收敛。
- 暂停/失败/完成释放槽，不让队首离线任务无限阻塞其它 peer。
- 接收端每 peer、全局均有资源上限；限流时返回可重试 Busy，不无限创建 task/文件。
- 建议按已准备好且可发送的任务使用等权 DRR（deficit round robin），以字节为 quantum。
- 共享连接的 QUIC 背压决定可用速度，不把上次 speedtest 结果当固定限速值。
- 某任务磁盘慢/peer 慢/暂停时跳过其暂不可用队列，其它任务用满剩余资源。
- 不能持有全局调度锁等待一个 peer 的网络 ACK；不能通过“开三个 tokio::spawn”宣称公平。
- 每任务缓存和全局缓存有字节上限；控制消息不被数据队列淹没；不建立 1 GiB 默认队列。
- 同瓶颈且同样就绪任务的长期份额应近似 1/N；跨 peer 不同 RTT/磁盘的瞬时速度不能保证相等。
- 采用可注入时钟的采样器：短窗口或 EMA 显示 MiB/s，暂停/断线归零；恢复重验已有 bytes 不计入当前网络速度。
- 完成百分比只用确认进度；不足 100% 与 Finalizing 分离；不得将发送进度当持久化完成。
- 空文件/空目录完成、零秒采样、整数溢出均测试。

## 10. 测速适配

复用 speedtest 模块，GUI 默认 30 秒；支持 60/120/.../600 秒。
现有 MAX_DURATION_SECS=300 需要有针对性扩展，CLI 文档及 300 边界测试一起调整；CLI 默认 10 秒可保留。
两方向都使用接收端实际 elapsed，不能重新引入 #18 已修复的发送方时间偏差。
取消要有协议/流生命周期处理，不留下 accept_uni 误接下次测速流；不能关闭共享连接导致无关任务损坏。
本版为避免测量污染，文件活动期间不接受新测速，测速期间不新发文件；接收侧同样做仲裁。
长时测试可缩时验证状态机，但至少 T012 有真实 600 秒测试证据，不用固定 Mbps 作为 CI 门槛。

## 11. 测试与可观察性

领域测试无需 GPUI display；所有定时逻辑尽量可注入时间，不靠 sleep 猜竞态。
分层：纯状态机/协议/路径 → 文件系统故障注入 → 环回双实例 → 原生桌面 → 真双 NAT。
见 TASKS.md 每阶段命令及验收矩阵。

日志有 task_id、peer_id（可短显）、connection generation、状态转移、checkpoint bytes/耗时；
不每片刷日志，不输出私钥、本机未选择的文件信息或完整目录树。
错误代码分层：配置、信令、认证、能力、路径、资源、源变更、磁盘、发布、网络中断。
UI 错误可操作，测试不能只断言“返回了任何 Err”。

## 12. 官方技术资料与验证责任

- GPUI：https://gpui.rs/ ，https://github.com/zed-industries/zed/tree/main/crates/gpui
- GPUI 组件生态：https://github.com/longbridge/gpui-kit （原 gpui-component 仓库发生过演进）
- Rust GPUI 发布信息：https://crates.io/crates/gpui
- 现有工程依赖与平台要求以实际 Cargo.lock 和原生测试为准。

这些链接用于 T001 调研，不能把网页展示平台支持当作本仓库已验证。若依赖镜像下载失败，记录环境原因；不得静默永久修改全局 Cargo 配置或提交开发机器专用镜像。
