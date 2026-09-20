# p2p_file

点对点（P2P）文件传输工具。**Rust** 实现，目标是**公网 NAT 穿透直连**，中继只作为兜底。

除了传文件，它还提供一个**通用 TCP 隧道**：把本机的一个端口转发到对端的任意服务上
（`ssh`、`rdp`、`http`……），全程点对点，业务数据不经过任何中转服务器。

## 当前状态

已经能用：**两台分别在不同 NAT 后面的机器，通过一台公网服务器牵线，打洞建立直连，
然后传文件或者开隧道。**

| 模块 | 状态 |
| --- | --- |
| `identity` — Ed25519 身份、节点 ID | ✅ 完成 |
| `protocol` — 清单、分片哈希、帧编解码 | ✅ 完成 |
| `protocol`/`transport` — 双向认证握手 | ✅ 完成 |
| `transport` — QUIC 数据通道 | ✅ 完成 |
| `storage` — 临时文件、位图、断点续传 | ✅ 完成 |
| `transfer` — 发送端 / 接收端 | ✅ 完成 |
| `nat::stun` — 手写 STUN（含 FINGERPRINT） | ✅ 完成 |
| `nat::classify` — NAT 映射行为判定 | ✅ 完成（仅映射行为，未含过滤行为） |
| `nat::punch` — UDP 同时打洞、保活、令牌鉴权 | ✅ 完成 |
| `discovery::signal` — 公网信令（牵线服务器） | ✅ 完成 |
| `tunnel` — 通用 TCP 端口转发 | ✅ 完成 |
| `discovery::mdns` — 局域网发现 | ✅ 完成 |
| `nat::portmap` — UPnP / NAT-PMP | 🚧 空壳（暂用 `--advertise` 手工替代） |
| 中继兜底（TURN / relay） | ⛔ 未开始（对称型 NAT 目前无解） |

## 快速开始

```bash
cargo build --release
BIN=./target/release/p2p_file
```

### 0. 准备：一台有公网 IP 的机器（云主机）

只需要它**牵线**——帮忙交换双方的地址，业务数据一个字节都不经过它，所以
1 核 1M 带宽都够用。

```bash
# 云主机上：放通安全组的 TCP 7000，然后跑起来
$BIN signal-server --listen 0.0.0.0:7000
```

### 1. 拿到两边的身份

在**两台**机器上各跑一次，把输出的节点 ID 记下来：

```bash
$BIN id
# 节点 ID: cb2a5052cdbfdcef7c294f1ae4960c7e
```

节点 ID 就是公钥的摘要，可以公开；私钥在 `~/.config/p2p_file/identity.key`，别外传。

### 2. 家里那台：常驻等着被连

```bash
# 允许 laptop 连进来；允许它转发到本机的 22 端口（ssh）；同时能收文件
$BIN serve \
  --signal 你的云主机:7000 \
  --allow <laptop的节点ID> \
  --forward 127.0.0.1:22 \
  --recv-dir ~/下载 \
  --port 9000
```

它会**一直等**着对端上线（不超时），空闲一段时间后自动重新打洞，
所以开着不管就行。要开机自启就交给 systemd（见下文）。

### 3. 在外面那台：开隧道或者推文件

```bash
# 把本机 2222 端口接到家里的 22 端口，然后 ssh -p 2222 127.0.0.1
$BIN tunnel \
  --signal 你的云主机:7000 \
  --peer <家里的节点ID> \
  --listen 127.0.0.1:2222 \
  --to 127.0.0.1:22

# 或者直接把文件推过去（落到家里的 --recv-dir）
$BIN push --signal 你的云主机:7000 --peer <家里的节点ID> ./大文件.mkv
```

### 其它命令

```bash
$BIN stun --server stun.cloudflare.com:3478   # 查自己在外网的样子和 NAT 类型
$BIN discover --timeout 5                     # 局域网里找对端
$BIN recv --listen 0.0.0.0:9000 --out-dir ./downloads   # 老式：直接监听收文件
$BIN send ./大文件.mkv 203.0.113.7:9000                  # 老式：直连地址发送
```

## 部署到云主机（systemd）

```ini
# /etc/systemd/system/p2p-signal.service
[Unit]
Description=p2p_file 信令服务器（只牵线，不过数据）
After=network-online.target

[Service]
ExecStart=/usr/local/bin/p2p_file signal-server --listen 0.0.0.0:7000
Restart=always
RestartSec=3
# 日志进 journald
StandardOutput=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now p2p-signal
journalctl -u p2p-signal -f
```

记得在**云厂商的安全组**里放通 TCP 7000（这是唯一需要对外开放的端口）。

## 家里那台也做成服务

```ini
# /etc/systemd/system/p2p-serve.service
[Unit]
Description=p2p_file 常驻服务（等着被连）
After=network-online.target

[Service]
User=你的用户名
ExecStart=/usr/local/bin/p2p_file serve \
  --signal 你的云主机:7000 \
  --allow <laptop的节点ID> \
  --forward 127.0.0.1:22 \
  --recv-dir /home/你的用户名/下载 \
  --port 9000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

程序同时处理 `SIGINT`（Ctrl-C）和 `SIGTERM`（`systemctl stop` 发的就是它），
所以停止服务时会优雅关闭 QUIC 连接，对端立刻就能察觉。

## 打不通的时候

按这个顺序查：

1. **看 NAT 类型**：`$BIN stun`。输出 `地址相关` 或 `地址无关` 说明能打洞；
   输出 `地址端口相关（对称型）` 就基本没戏，需要中继。
2. **两边都要在跑**：打洞是「同时开启」，只有一边在发包是打不通的。
   `serve` 常驻那台会自己重新打洞，不用管。
3. **手工端口映射**：在路由器上把 UDP 9000 映射到那台机器，然后加
   `--advertise 你的公网IP:映射出去的端口`。这是万能兜底，连对称型 NAT 都能过。
4. **两台机器要用同一个 `--port`**：NAT 映射是按本地端口分配的，
   `serve` 用 9000，对端也用 9000 最稳。

## 开发

```bash
cargo test              # 155 个测试
cargo clippy --all-targets
cargo fmt

./scripts/e2e.sh        # 真起三个进程跑一遍：牵线 → 打洞 → 隧道 → 推文件
```

架构与打洞原理见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 已实现的安全性质

- 通道加密：QUIC 自带 TLS 1.3。
- 身份认证：Ed25519 密钥对，节点 ID = 公钥的 BLAKE3 摘要，**自证**，不需要 CA。
- 双向认证握手：双方各自签名「双方公钥 + 双方随机数」，防冒名、防重放。
- 打洞令牌：每次牵线由信令服务器发一个 128 位随机令牌给双方；探测包带令牌
  才被认下，所以「接受任意来源的探测包」是安全的（见架构文档）。
- 转发白名单：`serve` 只允许转发到 `--forward` 明确列出的地址，且只接受 IP:port
  （不接受域名，避免 DNS 绕过白名单）。
- 节点白名单：`serve --allow` 之外的人连不上。
- 完整性：每个分片 BLAKE3 校验，清单有覆盖全字段的根哈希，收尾前双方核对根哈希。
- 落盘安全：先写 `.part` 临时文件，全部校验通过才改名；文件名经过清洗，挡住 `../` 路径穿越。

**注意**：信令服务器知道谁在跟谁说话（节点 ID 和 IP），但看不到任何业务数据。
