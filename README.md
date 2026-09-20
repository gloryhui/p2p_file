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

NAT 映射行为: 地址相关（可以打洞）
这个类型可以打洞，直接按 README 的步骤部署即可。
```

三个服务器看到同一个 IP 但**端口不同**，这就是「地址相关」——照样能打洞，
本项目专门为这种 NAT 做了令牌鉴权。

如果输出是 `地址端口相关/对称型（很难打洞）`，请直接跳到
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

1. **先看 NAT 类型**：`$BIN stun`。它会把结果直接判给你看（见第 3 步的输出示例）。
   判成 `对称型` 就基本没戏，只能走下面的第 3 条。

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
- 155 个单元测试，含地址相关映射（ADM）场景的打洞、令牌一致性、
  对端被强杀后的下线清理。

**只在真机上验证了一半**：

- 本机网络的 NAT 类型实测为「地址相关（可以打洞）」，正是需要令牌鉴权
  才能打通的类型 —— 这个判定逻辑是真的，但**两台真正处于不同 NAT 后面的
  机器之间的打洞，我没有条件实测**（需要两个独立网络）。
  相关逻辑由单元测试覆盖，第一次部署时请按上面的排查步骤确认。

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
cargo test                    # 155 个测试
cargo clippy --all-targets
cargo fmt --check

./scripts/e2e.sh              # 真起三个进程跑完整链路
./scripts/e2e.sh --release    # 用 release 版跑
```

架构、协议格式和踩过的坑见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 已实现的安全性质

- **通道加密**：QUIC 自带 TLS 1.3。
- **身份认证**：Ed25519 密钥对，节点 ID = 公钥的 BLAKE3 摘要，**自证**，不需要 CA。
- **双向认证握手**：双方各自签名「双方公钥 + 双方随机数」，防冒名、防重放。
- **打洞令牌**：每次牵线由信令服务器下发一个 128 位随机令牌给双方，探测包带令牌
  才被认下。所以「接受任意来源的探测包」是安全的（这是打通地址相关映射型 NAT 的关键）。
- **转发白名单**：`serve` 只允许转发到 `--forward` 明确列出的地址，且只接受
  `IP:port`（不接受域名，避免用 DNS 绕过白名单）。
- **节点白名单**：`serve --allow` 之外的人连不上。
- **完整性**：每个分片 BLAKE3 校验，清单有覆盖全字段的根哈希，收尾前双方核对。
- **落盘安全**：先写 `.part` 临时文件，全部校验通过才改名；文件名经过清洗，
  挡住 `../` 路径穿越。

信令服务器知道**谁在跟谁说话**（节点 ID 和 IP），但看不到任何业务数据。

## 开源协议

**MIT 与 Apache-2.0 双许可，两个许可同时生效。** 这不是一个待定的选择。

本项目对所有人**同时**授予这两个许可下的权利。使用本项目的人按自己方便的
那个来即可——比如公司法务只认 MIT，那就按 MIT；想用 Apache-2.0 的专利授权
条款，那就按 Apache-2.0。在自己项目里引用时写 `MIT OR Apache-2.0`。

- [MIT License](LICENSE-MIT)
- [Apache License 2.0](LICENSE-APACHE)

两个都给是 Rust 生态的惯例（`rustc`、`cargo`、`tokio`、`quinn` 都这么做）：
Apache-2.0 带明确的专利授权，对协议实现类项目有实际意义；MIT 更简短，
企业法务最容易过。两个并存，取长补短。

> GitHub 仓库侧边栏的协议只显示 `Apache-2.0`，那是因为它遇到多个协议文件时
> 只会挑一个显示，**不代表 MIT 无效**。以本文件和两个 LICENSE 文件为准。

**对本项目的贡献**：除非你明确声明，否则任何有意提交以纳入本项目的贡献，
均按上述双许可授权，不附加任何额外条款。
