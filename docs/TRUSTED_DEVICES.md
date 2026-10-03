# Trusted Device（Issue #55）

## 使用方式

首次连接输入对端设备 ID 和 Remote Password。连接或密码认证成功不会写入可信名单。
在连接页或设置页明确点击「信任此设备」，才允许这个真实 NodeId 以后免输入本机密码。
这是一项单向授权：B 信任 A，只允许 A 访问 B；B 访问 A 仍需密码或 A 的明确授权。
首次 Trust 必须有当前会话的 `inbound.password`：对端已证明知道本机密码。
A 输入 B 密码后，应由 B 手动信任 A；A 的 `outbound.password` 不能授权 B 访问 A。
GUI 按钮和 Session 后端都检查这个方向；Trusted-only、Short ID 或名称不能替代密码证明。

设置页的「可信设备」显示本地备注、历史 Short ID、真实 NodeId 和信任日期，支持复制
完整 NodeId、改名和取消信任。名称及 Short ID 只用于展示。连接页密码可留空，客户端
仍须完成真实身份验证并取得对端的 Trusted grant；不会根据输入号码提前认定可信。

## 身份、协议和授权来源

复用现有路径：Short ID 定位 → 打洞 → QUIC/TLS → 双方 Ed25519 身份及 TLS exporter
binding → Desktop 能力协商 → Remote Auth → 发布业务连接。CLI 协议不变。

`CAP_TRUSTED_DEVICE_AUTH` 是独立可选能力。密码交换的三个原有消息保持原序号与含义。
支持该能力的双方随后交换 `TrustedGrant`，使用新的 HMAC domain、当前 TLS binding、
双方 NodeId、当前挑战和递增序号验证确认。控制流只属于当前 QUIC transport；新连接
重新完成所有身份及授权步骤。旧 Desktop 客户端仍使用密码，不会静默获得可信授权。

`RemoteAuthorization` 分别记录 `inbound` / `outbound` 的 `password` 和 `trusted_device`。
最终权限是该方向两个来源的逻辑或。只有本机名单决定 inbound Trusted grant；只有
对端在当前认证控制流上的有效确认可以产生 outbound Trusted grant。可信授权不会清除
密码失败记录；只有本次真正成功的 inbound Password proof 才能清除对应记录。

## 持久化与撤销

Trusted Device 引入 schema v5；当前后台运行配置使用 schema v6，保留 v1–v5 迁移。可信记录包含完整规范 NodeId、
本地名称、可选历史 Short ID 和时间；拒绝重复身份及损坏配置。沿用原子替换、Unix
私有权限、AppData 目录和 symlink/reparse point 拒绝策略，不保存对端密码。

密码、可信名单和一般设置写入通过同一锁串行化；旧设置草稿不能覆盖最新安全字段。
可信操作先持久化，成功后才更新 runtime。添加信任还要再次核对当前连接、generation
以及真实 inbound Password grant；断线或旧 GUI 回调不能新增信任。密码轮换保留名单，撤销
旧 transport 后可在新的身份绑定连接上重新获得 Trusted grant。

网络会话不存在或 command channel 已关闭时，改名和撤销仍可持久化，包括保留关闭
handle 的情况。离线操作在配置写入锁内读取最新名单、只修改目标身份并安全原子写入；
损坏配置或链接路径会失败，GUI 仅在保存成功后更新名单。离线永远不能新增 Trust。

取消信任立即移除本机 inbound Trusted 来源并通知对端。业务流读取当前 transport 的
动态权限，按方向中断文件、测速和 Tunnel；仍有 Password grant 的方向继续运行。
单调撤销计数防止「撤销后立即重新信任」被 watch 合并，从而让旧业务流幸存。
旧 generation/transport 的控制回调不能修改新连接。控制流损坏或关闭只移除 Trusted
来源，保留仍有效的 Password grant。

`auto_start` 先连接配置中的真实 NodeId，完成身份与 outbound 授权后才绑定监听端口。
重启无需保存对端密码；对端不信任本机时继续等待人工密码。失去授权或 transport 后
关闭依赖的监听与活动流，新的认证完成后才能恢复。原有 Tunnel peer/target allowlist
仍然必须满足，可信授权不会扩大允许访问的服务。

## 回归覆盖

- 配置：空名单、显式持久化/重载、去重、改名/Short ID 备注、损坏及失败写入、密码
  轮换、旧草稿覆盖防护、并发写入、schema 迁移与既有链接/权限测试。
- Remote Auth：单向 Trusted only、Password only、混合来源精确撤销、密码失败统计、
  旧 capability、身份/挑战/TLS session/序号重放、认证中撤销、快速撤销再授权。
- Session：真实 Ed25519 连接上的手动信任、旧 generation 点击、失败写入不授权、
  outbound Password / Trusted-only 拒绝首次 Trust、关闭 handle 的改名/撤销及重启不恢复授权、
  断线拒绝信任、免密重启 auto_start、活动 Tunnel 撤销后密码恢复、双向文件传输中
  精确保留 Password 方向，以及既有文件/目录/恢复/测速/Tunnel allowlist 回归。
- GUI：按钮只基于已验证会话及 inbound Password 来源，排除本机、已可信、待认证和断线 peer；
  Short ID/名称相同不能产生信任，状态显示明确区分授权来源与方向。
- 三平台 GPUI workflow 运行完整 GUI 库测试、原生编译及打包；Windows full tests
  workflow 继续检查 CLI/NAT/storage 行为。
