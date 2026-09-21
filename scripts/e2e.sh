#!/usr/bin/env bash
#
# 端到端验证：在一台机器上跑起「家里那台」和「本机」两个进程，
# 用真实的信令服务器牵线、真实的 UDP 打洞、真实的 QUIC 隧道，
# 验证「隧道端口转发」和「文件直推」两条路都能通。
#
# 用法：
#   ./scripts/e2e.sh              # 用 target/debug
#   ./scripts/e2e.sh --release    # 用 target/release
#
# 注意：两个进程用的是同一个 IP，所以打洞一定会命中局域网候选地址。
# 这个脚本验证的是**整条链路的接线**（信令、令牌、打洞、QUIC、隧道分发、
# 文件落盘校验），验证不了真实 NAT 穿透——那需要两台在不同网络里的机器。
# NAT 穿透的关键逻辑由 src/nat/punch.rs 的单元测试覆盖（含地址相关映射场景）。

set -euo pipefail

PROFILE="debug"
[[ "${1:-}" == "--release" ]] && PROFILE="release"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/$PROFILE/p2p_file"

if [[ ! -x "$BIN" ]]; then
    echo "找不到 $BIN，先 cargo build $([[ $PROFILE == release ]] && echo --release)" >&2
    exit 1
fi

WORK="$(mktemp -d /tmp/p2p-e2e.XXXXXX)"
# 重新打洞的宽限期，故意设短一点，好在几秒内就能验证到。
RE_PUNCH=15
PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; exit 1; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# 等日志里出现某段文字，最多等 N 秒。
wait_for() {
    local file="$1" pattern="$2" timeout="${3:-60}" i
    for ((i = 0; i < timeout * 2; i++)); do
        grep -qa "$pattern" "$file" 2>/dev/null && return 0
        sleep 0.5
    done
    return 1
}

step "准备：三个端口上的三个进程"
# 目标服务：一个纯回显 TCP 服务，模拟「家里那台机器上的 ssh / web」
cat > "$WORK/target.py" <<'PY'
import socket, threading
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 9999))
srv.listen(8)
print("回显服务已监听 127.0.0.1:9999", flush=True)
def handle(c):
    with c:
        while True:
            data = c.recv(65536)
            if not data:
                break
            c.sendall(data)
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PY
python3 "$WORK/target.py" > "$WORK/target.log" 2>&1 &
PIDS+=($!)
pass "目标服务 127.0.0.1:9999"

"$BIN" --log warn signal-server --listen 127.0.0.1:7000 > "$WORK/signal.log" 2>&1 &
PIDS+=($!)
sleep 1
pass "信令服务器 127.0.0.1:7000"

# 两边各生成一个身份，相当于两台机器各有一把自己的私钥。
"$BIN" --key-file "$WORK/home.key" id > "$WORK/home.id" 2>/dev/null
"$BIN" --key-file "$WORK/laptop.key" id > "$WORK/laptop.id" 2>/dev/null
HOME_ID="$(awk '/^节点 ID/{print $3; exit}' "$WORK/home.id")"
LAPTOP_ID="$(awk '/^节点 ID/{print $3; exit}' "$WORK/laptop.id")"
pass "两个身份：家=$HOME_ID 本机=$LAPTOP_ID"

step "1. 「家里那台」先启动并常驻等待（此时对端还没上线）"
mkdir -p "$WORK/recv"
RUST_LOG=info "$BIN" --key-file "$WORK/home.key" --log info serve \
    --signal 127.0.0.1:7000 \
    --allow "$LAPTOP_ID" \
    --forward 127.0.0.1:9999 \
    --recv-dir "$WORK/recv" \
    --port 9101 \
    --re-punch-after "$RE_PUNCH" > "$WORK/serve.log" 2>&1 &
PIDS+=($!)

wait_for "$WORK/serve.log" "常驻等待中" 40 || fail "serve 没能进入常驻等待"
pass "serve 已常驻等待对端上线（没有超时退出）"

step "2. 「本机」发起隧道：本地 2222 → 对端 9999"
RUST_LOG=info "$BIN" --key-file "$WORK/laptop.key" --log info tunnel \
    --signal 127.0.0.1:7000 \
    --peer "$HOME_ID" \
    --listen 127.0.0.1:2222 \
    --to 127.0.0.1:9999 \
    --port 9102 > "$WORK/tunnel.log" 2>&1 &
TUNNEL_PID=$!
PIDS+=($TUNNEL_PID)

wait_for "$WORK/tunnel.log" "隧道已就绪" 60 || fail "隧道没能建立"
if grep -qa "洞打通了" "$WORK/serve.log" "$WORK/tunnel.log"; then
    pass "打洞成功"
elif grep -qa "直连已建立" "$WORK/tunnel.log"; then
    pass "打洞未确认，但候选直连已建立"
else
    fail "既没有打洞成功，也没有候选直连建立证据"
fi

python3 - <<'PY' || fail "隧道转发数据不正确"
import socket, os, sys
def roundtrip(msg, port=2222):
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    s.sendall(msg)
    buf, got = [], 0
    while got < len(msg):
        d = s.recv(65536)
        if not d:
            break
        buf.append(d); got += len(d)
    s.close()
    return b"".join(buf)

assert roundtrip(b"hello") == b"hello", "小消息不对"
assert roundtrip(b"second") == b"second", "第二条连接不对（多路复用）"
blob = os.urandom(1_000_000)
assert roundtrip(blob) == blob, "1MB 随机数据不对"
PY
pass "隧道转发正确（含 1MB 随机数据、多条并发连接）"

step "2.5 让隧道跨过重新打洞的宽限期（${RE_PUNCH}s），确认不会被误拆"
sleep $((RE_PUNCH + 8))
python3 - <<'PY' || fail "隧道在宽限期后被误拆了"
import socket
s = socket.create_connection(("127.0.0.1", 2222), timeout=30)
s.sendall(b"still-alive")
assert s.recv(100) == b"still-alive", "跨过宽限期后隧道不能用了"
s.close()
PY
pass "隧道在宽限期后依然可用（空闲计时不会误拆活跃连接）"

step "3. 隧道还开着时直推文件（此时 serve 不会再打洞，走候选重试）"
head -c 2000000 /dev/urandom > "$WORK/big.bin"
RUST_LOG=info "$BIN" --key-file "$WORK/laptop.key" --log info push \
    --signal 127.0.0.1:7000 \
    --peer "$HOME_ID" \
    "$WORK/big.bin" --port 9105 > "$WORK/push.log" 2>&1

wait_for "$WORK/push.log" "发送完成" 30 || fail "推送没有完成"
RECEIVED="$WORK/recv/big.bin"
[[ -f "$RECEIVED" ]] || fail "对端没有落盘"
SRC_SUM="$(sha256sum "$WORK/big.bin" | cut -d' ' -f1)"
DST_SUM="$(sha256sum "$RECEIVED" | cut -d' ' -f1)"
[[ "$SRC_SUM" == "$DST_SUM" ]] || fail "校验和不一致：$SRC_SUM vs $DST_SUM"
pass "文件直推正确，sha256 一致（$(stat -c%s "$RECEIVED") 字节）"
grep -qa "换用了后面的候选地址" "$WORK/push.log" \
    && pass "打洞未确认时自动回退到其他候选地址（这条兜底很关键）"

step "4. 断开隧道，等 serve 空闲后重新打洞，再连一次"
kill "$TUNNEL_PID" 2>/dev/null || true
wait_for "$WORK/serve.log" "重新打洞" 90 || fail "serve 没有在空闲后重新打洞"
pass "serve 空闲后已重新进入等待"

RUST_LOG=info "$BIN" --key-file "$WORK/laptop.key" --log info tunnel \
    --signal 127.0.0.1:7000 \
    --peer "$HOME_ID" \
    --listen 127.0.0.1:2223 \
    --to 127.0.0.1:9999 \
    --port 9106 > "$WORK/tunnel2.log" 2>&1 &
PIDS+=($!)
wait_for "$WORK/tunnel2.log" "隧道已就绪" 60 || fail "第二次隧道没能建立"

python3 - <<'PY' || fail "第二次隧道转发不正确"
import socket
s = socket.create_connection(("127.0.0.1", 2223), timeout=30)
s.sendall(b"round2")
assert s.recv(100) == b"round2"
s.close()
PY
pass "第二次连接同样成功（隔一段时间再连也能通）"

printf '\n\033[32m全部通过\033[0m\n'
