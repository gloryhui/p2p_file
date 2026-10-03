# 可选信令 TLS

信令默认保留明文 TCP 兼容模式。启用 TLS 后，客户端校验证书链、有效期和主机名；连接或验证失败不会尝试明文。服务器配置 TLS 的端口仅接受 TLS，不能在同一个端口兼容旧明文客户端。信令帧、登记签名、短 ID、心跳、候选交换和 Relay 票据协议保持不变。

## 服务器

准备与域名匹配的 PEM 证书链和 PEM 私钥，限制私钥文件的读取权限；证书文件应按叶证书、后续中间证书的顺序提供。运行：

```sh
p2p_file signal-server --listen 0.0.0.0:8900 \
  --short-id-db /var/lib/p2p-file/short-ids.sqlite3 \
  --tls-cert /etc/p2p-file/fullchain.pem \
  --tls-key /etc/p2p-file/privkey.pem
```

`--tls-cert` 和 `--tls-key` 必须同时提供。无效 PEM、私钥与证书不匹配或文件不可读会使启动失败。PEM 文件上限各为 4 MiB，只读取普通文件；错误不输出 PEM 内容。默认每次 TLS 握手最长 10 秒，最多同时进行 64 个 TLS 握手。超出容量的新连接被拒绝，超时后释放容量。

可继续添加现有 `--relay-listen` 等选项启用 UDP Relay。TLS 保护 TCP 信令，Relay 仍转发端到端加密的 QUIC datagram。证书或私钥轮换后需重启服务器，新连接加载新证书；此功能不自动部署、续签证书或修改远程服务。

## 命令行客户端

公网证书使用内置 Mozilla CA 根集合，不读取操作系统信任库。示例：

```sh
p2p_file serve --signal signal.example.com:8900 --signal-tls \
  --allow SENDER_NODE_ID --recv-dir ./received
p2p_file push --signal signal.example.com:8900 --signal-tls \
  --peer RECEIVER_NODE_ID ./example.zip
```

以上 ID 与文件参数按现有命令替换。`serve`、`push`、`tunnel`、`speedtest` 的 Direct 选项均支持 TLS；局域网 `send`/`recv` 不经过信令。

私有 CA 使用 `--signal-ca-file /absolute/path/ca.pem`，此时只信任该 PEM 中的 CA，替换内置根集合。地址使用 IP、证书使用域名时，添加 `--signal-server-name signal.example.com`，连接仍走指定 IP，但严格校验证书的该域名。未提供该选项时校验信令地址中的主机名；IP 地址要求证书包含对应 IP SAN。

```sh
p2p_file push --signal 192.0.2.10:8900 --signal-tls \
  --signal-ca-file /absolute/path/ca.pem \
  --signal-server-name signal.example.com \
  --peer RECEIVER_NODE_ID ./example.zip
```

CA/主机名选项要求显式 `--signal-tls`。TLS 没有忽略证书验证的开关。未知 CA、错误主机名、过期证书、错误 PEM 和明文服务器均使连接失败。证书准备在 TCP 连接前完成，TCP 和 TLS 握手各有 10 秒期限。重连和 Relay 的再次登记继续使用同一 TLS 策略。

## 桌面设置

在设置的高级网络区域启用「信令 TLS」，可填写私有 CA 的绝对文件路径及校验主机名；留空分别使用内置根集合、信令地址的主机名。点击保存后应用，未保存的开关和输入不会影响运行中的连接。保存会检查 CA 文件和主机名；失败时保留原配置。

schema 9 保存 TLS 策略。旧版本配置迁移后仍为明文，必须主动开启。已启用 TLS 后，即使 CA 文件被删除，加载设置也保留 TLS 策略，连接显示失败，不恢复明文。每次新连接都会重新读取 CA 文件；在原路径替换 CA 内容不会立即重建已有连接，在下次连接尝试或重启后应用。修改并保存地址、TLS 开关、CA 路径或主机名会重新登记，并撤销旧会话及业务授权，任务需按现有流程恢复。

连接诊断显示当前信令模式；只有当前策略下的登记成功才显示 TLS 校验成功。业务对端连通不替代信令证书验证；更改策略或信令掉线后旧的成功显示失效。脱敏导出只包含固定模式和状态，不包含 CA 路径、主机名、证书或私钥。

## 安全与验证边界

TLS 使用 Rustls 的安全默认 TLS 1.2/1.3 策略，服务端不请求 TLS 客户端证书；客户端身份仍由现有 Ed25519 登记签名证明。业务设备的 QUIC 自签证书及会话绑定身份认证保持原有方式。信令 TLS 保护客户端与服务器之间的传输，服务器仍知道节点、地址及牵线关系，也能拒绝服务；它不为转发消息增加设备间签名。

自动测试覆盖 TLS 登记/短 ID/查询/心跳、拒绝错误证书和无降级、握手容量与超时、配置迁移与保存失败、桌面信令重连和策略撤销。真实 CLI 进程通过 TLS 完成 Direct 文件传输；真实认证 Relay 在 TLS 信令下完成续传、双向测速、允许目标的多路隧道和新会话再次登记。全套原有明文回归继续执行。公网证书部署、真实桌面设置交互及证书运维仍需部署方验收。
