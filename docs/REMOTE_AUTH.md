# 短设备 ID 与远程访问认证（Issue #51）

Trusted Device 扩展及最新授权来源/撤销语义见 [TRUSTED_DEVICES.md](TRUSTED_DEVICES.md)。

## 身份与权限

`ShortId` 是信令服务器分配的公开地址；真实身份仍是由 Ed25519 公钥推导的
32 个十六进制字符 NodeId。密码授予当前 Desktop 会话的访问权限，不代替身份握手。
连接顺序为：短 ID 查询 → 原有候选/打洞 → QUIC/TLS → 双方 Ed25519 与 TLS
exporter binding 验证 → Desktop 能力协商 → Remote Auth → 业务连接发布。

`PeerLifecycle::Negotiating` 表示身份验证完成；`RemoteAuthPending` 表示尚未授权。
`Connected(RemoteAuthorization)` 携带两个独立方向：

- `inbound_authorized`：peer 证明知道本机密码，允许其新文件、测速控制和 Tunnel 请求。
- `outbound_authorized`：本机输入的对端密码获得有效 HMAC 确认，允许本机发起业务、
  发送队列执行及本地 Tunnel 使用此连接。

A 只知道 B 密码时，A 可以向 B 发文件、测速或访问 B 的授权 TCP target；B 不能
向 A 发起业务。原请求的测速下载数据、TCP 回包仍可返回，不代表反向访问授权。
接收任务恢复会新开 Offer stream，因此还要求发送方有 outbound 权限。
双方分别证明对方密码后才是双向访问。GPUI 按方向显示状态和启用操作；在已有
入站会话上主动输入密码会建立新连接并重新证明双方凭据，不继承旧连接授权。
失败、断线、退出会移除连接；重连必须生成新 challenge 并重新认证。
现有 Tunnel 还必须同时满足目标和真实 peer 的 allowlist，复用 `src/tunnel/mod.rs`。
CLI 长 NodeId、文件/测速协议，以及 `allowed_peers + forwards` 边界保持原有语义。

## SQLite 与信令兼容性

```sh
p2p_file signal-server --listen 0.0.0.0:7000 --short-id-db /var/lib/p2p-file/device-ids.sqlite3
```

默认数据库为工作目录的 `signal-device-ids.sqlite3`。生产部署应指定稳定的绝对路径，
目录须预先存在，备份时保留数据库；删除数据库会丢失原来的地址分配记录。
默认服务器 API 也使用持久化数据库，嵌入式测试须明确指定 `short_id_database: None`。

SQLite `PRAGMA user_version=2` 包含 `device_id_mapping`、单行 `short_id_sequence`
及持久的 `short_id_allocation_budget`。v1 在同一迁移事务中补充预算表，保持已有映射和 sequence。
identity 与 short ID 均有 UNIQUE 约束；数字范围为 100000000..999999999。
在注册的私钥签名通过后，以 `BEGIN IMMEDIATE` 查询已有映射、更新 last_seen，
或插入新映射并推进 sequence。整个事务提交后才回复注册成功。不使用 MAX()+1，
不回收号码；不同 SQLite 连接/进程共享同一文件时仍由数据库写锁串行发号。
锁等待上限 2 秒；耗尽、损坏、未知 schema、写失败均返回真实错误并回滚。
新数据库初始化也是事务；不导入或修改本地 `identity.key`。

新映射有三层独立预算，已有 identity 更新 last_seen/重连不消耗发号配额：

- 全局每 60 秒最多 120 个新映射；窗口/计数持久化在 SQLite，与 mapping/sequence
  在同一个 `BEGIN IMMEDIATE` 事务提交或回滚。重启或多进程不能重置全局额度。
- 单来源 IP 每 60 秒最多 10 个新映射；共用窗口实现，内存表最多 1024 项，清理过期项。
  IP 只用于资源限制，不作为身份。表满只限制新分配，不限制已有 identity 重连。
- 默认最多消耗 1,000,000 个持久映射槽位，不回收已消耗的号码。拒绝时不推进 sequence。

CLI 可通过 `--max-device-ids`、`--new-device-ids-per-minute`、
`--new-device-ids-per-ip-per-minute` 调整上限；设为 0 可冻结相应新分配。
全球/IP 窗口限制不能证明用户真实；持续低速或分布式刷号仍可能达到总量上限。
达到硬上限后已有设备仍可重连，新设备须由运维明确调整容量。
每 IP 配额为进程内预算，多实例/重启仍受持久全局配额和总量上限约束。

信令保留 v2 注册签名 transcript 和原有枚举序号。CLI 继续请求 v2，并收到原有
`Registered`。Desktop 明确请求 v3，收到新增 `RegisteredShort`；新增
`LookupShort`/`ShortResolved` 只返回真实 NodeId，再走原来的 NodeId Lookup。
v3 客户端遇到旧信令服务器会明确失败，不会静默退回无短 ID 的注册流程。

查询窗口 10 秒：每连接 5 次、每 IP 20 次；每连接 3 次无结果查询后窗口内停止
解析；IP 表最多 1024 项并清理过期项。限流与不存在统一返回无解析结果。
SQLite 阻塞作业共用现有配置 `max_pending_lookups` 的全局 semaphore，默认 64；
取消异步调用后，已开始的数据库作业仍持有 permit，直到实际结束。
信令协议没有密码、verifier、密码 proof 字段。

## 本地密码与配置迁移

6～12 位 ASCII 字母/数字；拒绝小型常见弱密码名单。自动生成 10 位密码，字符集为
`ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789`，使用 OS `getrandom`
和拒绝采样，避免取模偏差。salt 为 16 个随机字节。

认证配置 v1 固定 Argon2id 0x13、m=19456 KiB、t=2、p=1、输出 32 字节；参数
由版本定义，不能由远端请求任意成本。参数依据 [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
的最低 Argon2id 配置。实现使用 [RustCrypto Argon2](https://docs.rs/argon2/0.5.3/argon2/)。
磁盘只保存版本、salt、派生 key。SecretPassword/RemoteVerifier 的 Debug 脱敏，
密码/派生密钥封装在释放时清零；网络 proof 不实现 Debug。永久密码不进入信令、
QUIC 明文载荷、日志或诊断。

Desktop settings schema 升为 4：新增可选 `remote_auth`。v1/v2/v3 均可迁移；保留
旧网络设置与 Tunnel peer 权限，v2 原有目标权限继续 fail closed。首次初始化单独
原子写入认证配置，允许 `signal`/`receive_directory` 为空；正常“保存设置”仍要求
有效信令参数与可用接收目录。密码更新只修改已保存配置的认证部分，不把未保存的
Tunnel 草稿一起落盘。配置损坏时保留原文件并禁止覆盖。

复用原有私有目录、拒绝链接、create_new 临时文件、sync/rename/目录 sync 流程。
Unix 目录 0700、配置文件 0600；Windows 使用用户 AppData 目录继承的用户 ACL。
首次密码显示一次，之后默认隐藏，可显式显示/复制；修改或重新生成在后台派生并
持久化。重启后无法从派生密钥恢复密码，UI 明示需输入新密码或重新生成。
保存失败不会更新 runtime；保存成功后撤销已有连接和待认证任务、清空已有凭据，
等待 session 确认，再报告成功。密码轮换保留信令注册，避免重注册窗口影响立即重连。
应用失败则关闭网络会话，使用新配置重启。

## 认证协议

新增 Desktop capability `CAP_REMOTE_AUTH=256`；原有 framing/version 与枚举序号
不变。旧 peer 的基础能力协商仍可解析，但 session 必须拒绝缺少 Remote Auth 的
peer，不把它发布为可用业务连接。

在身份与能力协商之后，QUIC dialer 打开专用双向 auth stream。每帧为原有 u32 LE
长度前缀 + `P2PA\x01` + postcard AuthMessage，单帧上限 1024 字节：

1. 双方发送 `Challenge { version: 1, salt, nonce: random[32] }`。
2. 持有用户输入的对端密码的一方计算对端 salt 对应的 key 并发送 `Proof(Some(mac))`；
   未主动提交密码的一方发送 `Proof(None)`。
3. 双方验证收到的 proof 并发送 `Result { accepted, confirmation }`。错误统一返回认证失败/受限。

HMAC-SHA256 输入依次为：固定域 `p2p_file/desktop/remote-auth/v1`、u16 LE 版本、
salt、nonce、证明方真实 NodeId、验证方真实 NodeId、当前连接原有 TLS exporter
binding。使用 HMAC `verify_slice` 恒定时间比较。修改 nonce、设备身份、版本或当前
TLS 会话都会使旧 proof 失效。未知 challenge 版本在执行 KDF 前拒绝。

QUIC 发起方按 NodeId 排序，与用户点击连接的方向不同，因此采用双方 challenge。
验证对端 proof 只授予 inbound 权限；本机提交密码并验证对端成功确认只授予
outbound 权限。成功回复附带同一 transcript、独立域
`p2p_file/desktop/remote-auth/accepted/v1` 的 HMAC，证明验证方持有派生 key。
单独 `Result(true)` 或反射客户端 proof 都不能授权，包括本机已提交密码时。
至少一个方向有效才保留业务连接；另一方向的请求仍必须拒绝。入站错误 proof 的
失败计数不会因为出站确认成功而被清空；只有本机验证入站 proof 成功才清空该桶。
输入密码只在当前进程内按 peer 保存，数量最多 16，便于当前运行中的重新认证；
不持久化，不构成 Trusted Device，修改本机密码/信令配置会清空这些凭据。

整个交换 45 秒 deadline；KDF 最多两个后台作业，取消后 permit 由真实作业持有。
认证失败按已经 Ed25519 验证的 NodeId 计数：前 3 次不额外延迟，第 4 次 500ms、
第 5 次 1 秒，逐步增加至第 9 次 16 秒，第 10 次起冷却 60 秒。最多 256 个 peer，
15 分钟过期。表满先清理过期项，再淘汰最久未失败的旧项以接纳新失败记录；
容量不再拒绝未见过的正常 peer。淘汰可能使旧 identity 的失败历史丢失，但保留的
桶继续按 NodeId 退避，不形成全局长时间锁定。冷却与等待均可取消，不阻塞网络线程或其他 peer。

## Tunnel auto_start

对端密码不落盘。新进程没有当前 peer 凭据时，auto_start 规则进入
`WaitingAuthorization`，GPUI 显示“等待输入对端密码 / 授权”；不绑定 TCP listener，
不发起注定缺失密码的认证。用户随后按该 peer 输入正确密码、取得 outbound 权限后，
等待的规则自动继续启动，无须再次点击启动。停止、停用或删除等待规则会取消其
待启动意图；已有错误或缺失 capability 不会绕过认证。手动启动同样遵守此边界。

## 同地址重连与权限升级

short ID 解析与直接 NodeId 输入共用显式凭据升级流程；已有入站会话不会因为
解析成功而自动变成出站授权，必须建立新 transport 并重新验证当前 TLS binding。
普通候选地址刷新保留有效连接。同一地址上的 peer 实际重新打洞时，协调器通过
Quinn 现有单一 UDP 接收分发器观察新配对令牌：每 peer 最多保留两个令牌，
6 秒过期，最多 16 个 peer，底层总路由上限 48。仅查询或未知令牌不能触发重连；
匹配探测只触发新一轮打洞、真实身份、capability 与 Remote Auth 检查，不携带旧权限。

## 验证与限制

测试覆盖顺序/稳定/并发发号、双 UNIQUE、sequence/mapping 写失败回滚、锁与耗尽、
损坏/版本迁移、注册证明失败不占号、查询各层限流、密码规则与脱敏、当前 QUIC
上的正确/错误/缺失密码、反向拨号、伪造成功回复、认证前业务帧、nonce/identity/
version/TLS binding 重放、认证等待超时、失败冷却隔离/容量/清理、真实 short ID
连接与密码轮换撤销、单向/双向业务授权、满 failure table 后正常认证、持久刷号预算与
auto_start 等待后自动恢复，以及既有文件、测速、Tunnel 和进程退出/恢复 E2E。

验证命令与三平台 Actions 的实际结果记录在 PR。CI 验证构建、测试、打包链，
Windows/macOS 的交互式 GPUI 输入、剪贴板和本机双设备体验仍需人工验收。

此设计按 Issue 使用密码派生 key + challenge-response，未实现 PAKE，因此不提供
抗离线猜测保证；默认随机 10 位密码优于较短自定义密码。授权方向绑定当前会话；
不提供账号、Trusted Device、密码找回、2FA、屏幕共享、远控、TURN、中继、ID 自选/
回收/转让或 UPnP/NAT-PMP/PCP。
