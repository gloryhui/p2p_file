# p2p_file

点对点（P2P）直连工具。**Rust** 实现，靠 NAT 穿透建立直连：

- **传文件** —— 分片、BLAKE3 逐片校验、断点续传。
- **通用 TCP 隧道** —— 把本机一个端口转发到对端的任意服务（`ssh`、`rdp`、`http`……）。

两种情况下的业务数据都是**点对点**的。中间只需要一台公网机器帮忙**牵线**
（交换双方的地址），它一个字节的业务数据都看不到。

## 快速开始

整个流程你只需要提供 **3 个值**：

| 值 | 是什么 | 怎么拿到 |
| --- | --- | --- |
| 云主机地址 | 你那台有公网 IP 的机器的 `IP:端口` | 自己知道，例如 `203.0.113.7:7000` |
| 家里的节点 ID | 家里那台机器的身份 | 在那台机器上跑 `p2p_file id` |
| 外面的节点 ID | 外面那台机器的身份 | 在那台机器上跑 `p2p_file id` |

下面每台机器的命令块，开头都把需要的值导出成变量，**填一次，后面的命令整段复制粘贴即可**。
文中出现的 `203.0.113.7` 和那两个节点 ID 都是示例值。

### 编译

```bash
cargo build --release
export BIN=$PWD/target/release/p2p_file
```

把 `$BIN` 拷到要用的机器上（`scp` 就行）：

```bash
scp target/release/p2p_file root@203.0.113.7:/usr/local/bin/p2p_file
```

`203.0.113.7` 就是你云主机的公网 IP，全文的示例都用它。

### 第 1 步：云主机 —— 跑信令服务器

```bash
export SIGNAL=0.0.0.0:7000
$BIN signal-server --listen $SIGNAL
```

记得在**云厂商的安全组**里放通 TCP 7000。这是唯一需要对外开放的端口。

它只做牵线，1 核 1M 带宽都绰绰有余。开机自启见[部署](#部署为-systemd-服务)。

### 第 2 步：两台机器各拿一次身份

在**家里那台**和**外面那台**上分别跑：

```bash
$BIN id
```

输出形如：

```
节点 ID:  a1b2c3d4e5f60718293a4b5c6d7e8f90
公钥:     3b99296d64377f91605631f89feb53aec6e432dd8b0a0e15a59267de106b04f9
密钥文件: /home/you/.config/p2p_file/identity.key
```

要的就是 `节点 ID:` 后面那串 **32 位十六进制**。它是公钥摘要，可以随便公开。
私钥自动生成在 `~/.config/p2p_file/identity.key`（权限 `0600`），**别外传**。
两台机器的 ID 记下来，第 4、5 步要用。

### 第 3 步：先确认打洞打得通

```bash
$BIN stun
```

输出形如：

```
本地端口 59744，向 3 个 STUN 服务器查询 ...

  111.206.174.2:3478           看到的是 39.151.73.136:10281
  74.125.250.129:19302         看到的是 39.151.73.136:10282
  162.159.207.0:3478           看到的是 39.151.73.136:10282

NAT 映射行为: 未知（证据不足）
mapping 证据: 证据不足（服务器不支持 RFC 5780 行为发现或备用探测失败）
Filtering behavior: 未测量（当前只测 mapping）
证据不足时不能宣称 NAT 可以打洞。
```

程序会优先使用支持 RFC 5780 `OTHER-ADDRESS` 的 STUN 服务器，对同一个 socket
按 RFC 5780 §4.3 先探测 primary IP+port，再探测 alternate IP+primary port；只有
Test II 映射与 Test I 不同，才继续探测 alternate IP+alternate port。只有 RFC 5780
行为发现证据充分时，才会区分 EIM / ADM / APDM；跨 IP 且每个 IP 只有一个样本时会保持未知。
当前只测 mapping，不测 filtering，因此任何 mapping 结果都不能单独等同于最终 punchability。

如果输出是 `地址端口相关/对称型（mapping 对打洞不利）`，请直接跳到
[打不通的时候](#打不通的时候)第 3 条做端口映射。

### 第 4 步：家里那台 —— 常驻等着被连

```bash
export SIGNAL=203.0.113.7:7000        # 换成你云主机的公网地址
export LAPTOP_ID=0f1e2d3c4b5a69788796a5b4c3d2e1f0    # 换成"外面那台"的节点 ID

$BIN serve \
  --signal $SIGNAL \
  --allow $LAPTOP_ID \
  --forward 127.0.0.1:22 \
  --recv-dir ~/下载 \
  --port 9000
```

这条命令的含义：

- `--allow` —— 只让这一个节点连进来，别人不行。
- `--forward 127.0.0.1:22` —— 允许对端转发到本机的 ssh。可以重复指定多个。
- `--recv-dir` —— 对端推过来的文件落在这里。目录不存在会自动创建。
- `--port 9000` —— 打洞用的本地端口。

它会**一直等**着对端上线（不超时），空闲一段时间后自动重新打洞，
所以开着不用管。要做成开机自启见[部署](#部署为-systemd-服务)。

### 第 5 步：外面那台 —— 开隧道或推文件

```bash
export SIGNAL=203.0.113.7:7000        # 换成你云主机的公网地址
export HOME_ID=a1b2c3d4e5f60718293a4b5c6d7e8f90       # 换成"家里那台"的节点 ID
```

**开隧道**（把本机 2222 接到家里的 22）：

```bash
$BIN tunnel \
  --signal $SIGNAL \
  --peer $HOME_ID \
  --listen 127.0.0.1:2222 \
  --to 127.0.0.1:22

# 另开一个终端：
ssh -p 2222 127.0.0.1
```

（`ssh` 不带用户名时会用你当前的用户名。家里那台的登录名不一样的话，
写成 `ssh -p 2222 那边的用户名@127.0.0.1`。）

`--to` 指定的地址必须在家里那台的 `--forward` 白名单里，否则会被拒绝。

**推文件**（落到家里的 `--recv-dir`）：

```bash
$BIN push --signal $SIGNAL --peer $HOME_ID ./大文件.mkv
```

### 原生桌面（GPUI）

```bash
cargo run --locked --features gui --bin p2p-desktop
```

首次打开设置，填写自己的信令主机/IP 和端口、选择本机接收目录并保存。接收端上线后可以等待；发送端粘贴接收端完整 ID，身份认证成功后选择文件或目录直接入队。并发数 1/2/3 保存后应用，任务可暂停并按原 TaskID 继续。测速支持发送/接收、30 秒或 1–10 分钟；有文件活动时先暂停，不会自动暂停用户任务。

设置说明可信设备 MVP 的接收边界：知道 ID 的节点可发送文件。接收目录修改只影响新任务，对端输入框修改不改变旧任务绑定。Linux 系统文件选择器需要可用的 desktop portal。原生窗口操作与截图见 [T010 验证证据](docs/gpui-mvp/evidence/t010-ui-validation.md)；跨物理平台、Wayland、中文 IME、双 NAT 和安装包验收仍在后续流水线中记录。

桌面进程恢复与故障验证：`python3 scripts/desktop-e2e.py --output /tmp/desktop-e2e-new-evidence`；支持 Linux/Windows/macOS 的测试二进制，输出可审计矩阵。它验证真实 Session/OS 进程与 loopback，不代表物理设备或双 NAT；细节见 [T011 矩阵](docs/gpui-mvp/evidence/t011-process-matrix.md)。端点重启后显式连接、再继续原任务，不自动恢复文件。

### P2P / QUIC 纯网络测速

测速 CLI 默认仍为 10 秒，`--duration` 支持 1–600 秒。桌面测速业务支持 30 秒或 1–10 分钟，原生界面已接入文件/目录、暂停/继续和测速按钮。长时边界由可控时钟回归验证；真实 600 秒与双 NAT 证据以 [GPUI 总控 Issue #24](https://github.com/gloryhui/p2p_file/issues/24) 为准。

想把网络链路和文件传输本身区分开时，在外面那台机器上运行：

```bash
$BIN speedtest \
  --signal $SIGNAL \
  --peer $HOME_ID
```

也可以指定时长、方向和固定内存 block：

```bash
$BIN speedtest \
  --signal $SIGNAL \
  --peer $HOME_ID \
  --duration 15 \
  --direction upload \
  --block-size 1048576
```

`speedtest` 是经过现有信令、STUN/候选、UDP 打洞、QUIC 和 Ed25519 身份认证后的
内存到内存测速。它不读写磁盘，不计算文件 hash，不使用 manifest、bitmap、fsync
或文件分片协议；因此它不是 ISP 官方测速，而是用来和 `push` 速度做对照。
`--direction both` 会先 upload、再 download，不做同时双向测速。

- `speedtest` 快、`push` 慢：优先检查文件协议、磁盘和 fsync。
- `speedtest` 慢、`push` 慢：优先检查 QUIC、UDP、RTT、丢包、流控或 ISP。
- `speedtest` 快、`push` 快：当前链路和文件路径都正常。

## 部署为 systemd 服务

两个服务都用**用户级 unit**，这样路径里不用写死用户名。

### 云主机上的信令服务器

```ini
# /etc/systemd/system/p2p-signal.service
[Unit]
Description=p2p_file 信令服务器（只牵线，不过数据）
After=network-online.target

[Service]
ExecStart=/usr/local/bin/p2p_file signal-server --listen 0.0.0.0:7000
Restart=always
RestartSec=3
StandardOutput=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now p2p-signal
journalctl -u p2p-signal -f
```

### 家里那台的常驻服务

```ini
# ~/.config/systemd/user/p2p-serve.service
[Unit]
Description=p2p_file 常驻服务（等着被连）

[Service]
ExecStart=%h/bin/p2p_file serve \
  --signal 203.0.113.7:7000 \
  --allow 0f1e2d3c4b5a69788796a5b4c3d2e1f0 \
  --forward 127.0.0.1:22 \
  --recv-dir %h/下载 \
  --port 9000
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
```

`%h` 会自动展开成当前用户的家目录，所以路径不用改。启用：

```bash
systemctl --user daemon-reload
systemctl --user enable --now p2p-serve
# 让它在你不登录的时候也活着（关键，否则注销就停了）
loginctl enable-linger $USER
journalctl --user -u p2p-serve -f
```

程序同时处理 `SIGINT`（Ctrl-C）和 `SIGTERM`（`systemctl stop` 发的就是它），
停止时会优雅关闭 QUIC 连接，对端立刻就能察觉，不用干等超时。

## 打不通的时候

按顺序排查：

1. **先看 NAT mapping**：`$BIN stun`。只有报告明确显示 RFC 5780 行为发现证据充分时，
   分类结果才有判别力；filtering 未测量，不能把 mapping 结果当成最终“可打洞”结论。

2. **确认两边都在跑**。打洞是「同时开启」——只有一边发包是打不通的。
   `serve` 那台常驻会自动重新打洞，不用管。

3. **手工端口映射（万能兜底）**。在路由器上把 UDP 9000 映射到家里那台机器，
   然后给它加 `--advertise`：

   ```bash
   --advertise 203.0.113.7:9000      # 填路由器上映射出来的那个「公网 IP:端口」
   ```

   这样连对称型 NAT 都能过。

4. **两台机器用同一个 `--port`**。NAT 映射是按本地端口分配的，
   两边都写 9000 最稳。

日志是排查的主要依据，加 `--log info` 能看到打洞过程：

```bash
$BIN --log info tunnel --signal $SIGNAL --peer $HOME_ID --listen 127.0.0.1:2222 --to 127.0.0.1:22
```

## 验证到什么程度

说清楚哪些是实测过的、哪些只是设计上应该成立：

**实测过**（`./scripts/e2e.sh`，每次改代码都会跑）：

- 真起三个进程跑完整链路：信令牵线 → UDP 打洞 → QUIC 直连 → 隧道转发 → 文件落盘校验。
- 隧道搬运 1MB 随机数据无损，支持多条并发连接。
- 文件直推 2MB，sha256 一致。
- 断开后 `serve` 重新打洞，再连一次仍然成功。
- 测试覆盖 RFC 5780 mapping 状态机、证据不足、地址相关映射（ADM）样本、令牌一致性、
  对端被强杀后的下线清理、信令注册认证与资源上限，以及畸形 `FileManifest` 的
  完整校验（`chunk_size=0` / 越界 / 分片数不符 / 根哈希错 / 极端长度都不 panic）。

**只在真机上验证了一半**：

- 本机网络的 mapping 结论只有在 RFC 5780 行为发现证据充分时才会报告（EIM 可在
  Test II 短路）；当前 CLI 不会
  把 ADM 或 PunchToken 描述成必然可打洞。**两台真正处于不同 NAT 后面的机器之间的
  打洞，我没有条件实测**（需要两个独立网络）。

**没做**：

- 对称型 NAT 的中继兜底（TURN / relay）。
- UPnP / NAT-PMP 自动端口映射（`nat::portmap` 是空壳，暂时用 `--advertise` 手工替代）。
- IPv6：目前只绑 IPv4。IPv6 通常没有 NAT，能直连就省掉大半麻烦，是下一步的优先项。

## 局域网直连（不经过信令服务器）

两台机器在同一个局域网里时，不需要云主机：

```bash
# 接收方
$BIN recv --listen 0.0.0.0:9000 --out-dir ./downloads

# 发送方（先用 discover 找到对端地址）
$BIN discover --timeout 5
$BIN send ./大文件.mkv 192.168.1.7:9000
```

## 开发

```bash
cargo test                    # 222 个测试（221 单元 + 1 集成）
cargo clippy --all-targets
cargo fmt --check

./scripts/e2e.sh              # 真起三个进程跑完整链路
./scripts/e2e.sh --release    # 用 release 版跑
```

架构、协议格式和踩过的坑见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 已实现的安全性质

- **通道加密**：QUIC 自带 TLS 1.3。TLS 证书是**自签**的，不依赖 CA。
- **身份认证**：Ed25519 密钥对，节点 ID = 公钥的 BLAKE3 摘要，**自证**，不需要 CA。
- **双向认证握手，签名绑定当前 TLS 会话**：双方各自签名「双方公钥 + 双方随机数 +
  当前 QUIC/TLS 会话导出的绑定值」，防冒名、防重放。绑定值来自当前会话的 TLS
  exporter（RFC 5705），不同会话导出的值不同，所以签名只对**这一条**会话有效。
- **打洞令牌**：每次牵线由信令服务器下发一个 128 位随机令牌给双方，探测包带令牌
  才被认下。令牌只认证探测包属于本次会话、防止未知来源被误认；它不保证任何 NAT
  类型一定能穿透，也不替代 mapping/filtering 证据。
- **信令登记认证**：登记是 challenge-response，签名覆盖「服务器随机 challenge + 节点 ID +
  公钥 + 候选地址哈希」，既证明持有私钥、又防重放（明文信令上光看
  `node_id = hash(public_key)` 并不构成认证）。**这条签名保护的只是「客户端 → 服务器」的
  登记内容**：它让服务器确信「这个连接确实持有该私钥、候选没被改过」。服务器随后转发给
  对端的 `PeerCandidates`/打洞令牌**没有**端到端签名或加密，链路上的主动攻击者可以篡改
  它们，把打洞引到错误的地址、造成连接失败（DoS）。这不会让攻击者冒充业务对端——
  业务身份仍由 QUIC 之上的应用层握手确认（见下）。
  信令服务器同时还限制每条连接只能登记一个身份、限制了候选地址/在线节点/等待队列的数量，
  并用连接所有权避免旧连接误删新记录、主动断开被取代的旧连接、把等待状态绑定到具体连接。
  客户端后台按 `DEFAULT_HEARTBEAT_INTERVAL` 自动心跳，所以正常持有的长连接不会因为空闲
  被服务器误摘（只有超过空闲超时都没有任何帧，才会被清理）。
- **转发白名单**：`serve` 只允许转发到 `--forward` 明确列出的地址，且只接受
  `IP:port`（不接受域名，避免用 DNS 绕过白名单）。
- **节点白名单**：`serve --allow` 之外的人连不上。
- **完整性**：每个分片 BLAKE3 校验，清单有覆盖全字段的根哈希，收尾前双方核对。
  根哈希只防**链路中间**的篡改，不防发送端本身——所以所有来自网络的清单在首次
  使用前都必须过 `FileManifest::validate()`：分片大小在 16 KiB..=16 MiB、
  分片数与 `total_len` 精确一致、分片数放得进 `u32`、根哈希自洽；任一项不过
  只返回协议错误，绝不 panic、也不按对端声称的长度分配内存。
  `from_bytes()` / `ControlMessage::decode()` 都走完整校验，接收端与落盘层再各
  复查一次；发送端的 `--chunk-size` 由 CLI 提前拒绝，`manifest_from_reader()`
  在分配缓冲区之前也会再校验一次。
- **落盘安全**：先写 `.part` 临时文件，全部校验通过才改名；文件名经过清洗，
  挡住 `../` 路径穿越。

证书自签、客户端跳过证书校验，这些都是**有意**的：证书不承担身份，身份完全由
Ed25519 握手承担。但光有握手还不够——如果签名不绑定当前会话，中间人可以建立
`A ↔ M ↔ B` 两条独立连接，把 `Hello / HelloAck / Auth` 原样搬过去，让两边都验证通过。
现在签名覆盖了当前会话绑定值，这种转发必然验不过，**中间人无法透明代理握手**。

信令服务器知道**谁在跟谁说话**（节点 ID 和 IP），但看不到任何业务数据；登记内容
已由私钥签名认证，所以没人能冒充别人的节点 ID 去登记。

安全边界要说准确：信令走的是**明文 TCP**，而且注册签名的保护范围只到
「客户端 → 服务器」这一段。服务器转发给对端的候选地址与打洞令牌既没有端到端签名、
也没有加密——路径上的主动攻击者可以篡改它们制造 DoS（例如把对端地址换成不可达的），
但无法借此冒充业务对端：最终身份由 QUIC 之上的 Ed25519 应用层握手确认，业务数据也
始终在 QUIC/TLS 里加密传输。信令服务器能看到谁在跟谁说话，也能单方面拒绝服务。

## 开源协议

[MIT](LICENSE)。

随便用：商用、闭源修改、再发布、卖钱、再许可，全都可以。唯一的要求是
保留版权声明和许可声明。
