# p2p_file

点对点（P2P）文件传输工具。**Rust** 实现，目标是**公网 NAT 穿透直连**，中继只作为兜底。

## 当前状态

骨架已经能跑通端到端传输：

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
| `nat::punch` — UDP 同时打洞、保活 | ✅ 完成（未接入中继对齐） |
| `discovery::mdns` — 局域网发现 | ✅ 完成 |
| `discovery::signal` — 公网信令 | 🚧 空壳：线格式已定，收发未实现 |
| `nat::portmap` — UPnP / NAT-PMP | 🚧 空壳 |
| 中继兜底（TURN / relay） | ⛔ 未开始 |

**换句话说：局域网/已知地址直传已经可用；跨公网的全自动打洞还差信令服务器这一步。**
当前 `send` 需要一个能直连的地址；`discover` 能在局域网里找到对端。

## 快速开始

```bash
cargo build --release

# 看一眼自己的身份（首次会自动生成密钥）
./target/release/p2p_file id

# 接收方：监听并保存到 ./downloads
./target/release/p2p_file recv --listen 0.0.0.0:9000 --out-dir ./downloads

# 发送方
./target/release/p2p_file send ./大文件.mkv 203.0.113.7:9000

# 查自己在外网的样子
./target/release/p2p_file stun --server stun.cloudflare.com:3478

# 局域网里找对端
./target/release/p2p_file discover --timeout 5
```

开发：

```bash
cargo test        # 118 个测试
cargo clippy --all-targets
cargo fmt
```

架构与打洞原理见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 已实现的安全性质

- 通道加密：QUIC 自带 TLS 1.3。
- 身份认证：Ed25519 密钥对，节点 ID = 公钥的 BLAKE3 摘要，**自证**，不需要 CA。
- 双向认证握手：双方各自签名「双方公钥 + 双方随机数」，防冒名、防重放。
- 完整性：每个分片 BLAKE3 校验，清单有覆盖全字段的根哈希，收尾前双方核对根哈希。
- 落盘安全：先写 `.part` 临时文件，全部校验通过才改名；文件名经过清洗，挡住 `../` 路径穿越。
