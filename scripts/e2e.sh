#!/usr/bin/env bash
#
# 端到端验证：在一台机器上跑起「家里那台」和「本机」两个进程，
# 用真实的信令服务器牵线、原生 IPv4/IPv6 直连或可选认证 UDP Relay、真实的 QUIC 隧道，
# 验证「隧道端口转发」和「文件直推」两条路都能通。
#
# 用法：
#   ./scripts/e2e.sh              # 用 target/debug
#   ./scripts/e2e.sh --release    # 用 target/release
#
# 注意：Direct fixture 的两个进程使用同一个 IP，可命中局域网候选地址；
# Relay fixture 使用受控直连黑洞，UDP Relay 只转发设备间端到端加密的 QUIC datagram。
# 这个脚本验证的是**整条链路的接线**（信令、令牌、打洞、QUIC、隧道分发、
# 文件落盘校验），验证不了真实 NAT 穿透——那需要两台在不同网络里的机器。
# NAT 穿透的关键逻辑由 src/nat/punch.rs 的单元测试覆盖（含地址相关映射场景）。

set -euo pipefail

PROFILE="debug"
NATIVE_FAMILY="ipv4-only"
RELAY_MODE=false
for option in "$@"; do
    case "$option" in
        --release) PROFILE="release" ;;
        --ipv6) NATIVE_FAMILY="ipv6-only" ;;
        --relay) RELAY_MODE=true ;;
        *) echo "未知参数: $option" >&2; exit 1 ;;
    esac
done
DIRECT_OPTIONS=(--ip-family "$NATIVE_FAMILY" --stun 127.0.0.1:9)
if [[ "$NATIVE_FAMILY" == "ipv6-only" ]]; then
    DIRECT_OPTIONS=(--ip-family ipv6-only --stun '[::1]:9')
fi
if [[ "$RELAY_MODE" == true ]]; then
    DIRECT_OPTIONS+=(--relay 127.0.0.1:7001 --advertise-only)
fi
advertise_address() {
    if [[ "$RELAY_MODE" == true ]]; then set -- "$(( $1 + 1000 ))"; fi
    if [[ "$NATIVE_FAMILY" == "ipv6-only" ]]; then printf '[::1]:%s' "$1"; else printf '127.0.0.1:%s' "$1"; fi
}

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
fail() { for logfile in "$WORK"/*.log; do echo "$logfile"; tail -40 "$logfile"; done; printf '  \033[31m✗\033[0m %s\n' "$1"; exit 1; }
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

step "准备：$NATIVE_FAMILY 原生 P2P，IPv4 信令和 TCP 目标"
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

RELAY_SERVER_OPTIONS=()
if [[ "$RELAY_MODE" == true ]]; then
    RELAY_SERVER_OPTIONS=(--relay-listen 127.0.0.1:7001)
    # Held UDP ports deliberately never respond; candidates differ from real Quinn ports.
    python3 -u - <<'PYBH' > "$WORK/blackholes.log" 2>&1 &
import socket, time
sockets = []
for port in (10101, 10102, 10103, 10105, 10106):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    sockets.append(s)
print("blackholes ready", flush=True)
while True:
    time.sleep(60)
PYBH
    PIDS+=($!)
    wait_for "$WORK/blackholes.log" 'blackholes ready' 5 || fail 'blackhole fixture failed'
fi
"$BIN" --log warn signal-server "${RELAY_SERVER_OPTIONS[@]}" --listen 127.0.0.1:7000 --short-id-db "$WORK/device-ids.sqlite3" > "$WORK/signal.log" 2>&1 &
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
    --signal 127.0.0.1:7000 "${DIRECT_OPTIONS[@]}" \
    --allow "$LAPTOP_ID" \
    --forward 127.0.0.1:9999 \
    --recv-dir "$WORK/recv" \
    --port 9101 --advertise "$(advertise_address 9101)" \
    --re-punch-after "$RE_PUNCH" > "$WORK/serve.log" 2>&1 &
PIDS+=($!)

wait_for "$WORK/serve.log" "常驻等待中" 40 || fail "serve 没能进入常驻等待"
pass "serve 已常驻等待对端上线（没有超时退出）"

step "2. 「本机」发起隧道：本地 2222 → 对端 9999"
RUST_LOG=info "$BIN" --key-file "$WORK/laptop.key" --log info tunnel \
    --signal 127.0.0.1:7000 "${DIRECT_OPTIONS[@]}" \
    --peer "$HOME_ID" \
    --listen 127.0.0.1:2222 \
    --to 127.0.0.1:9999 \
    --port 9102 --advertise "$(advertise_address 9102)" > "$WORK/tunnel.log" 2>&1 &
TUNNEL_PID=$!
PIDS+=($TUNNEL_PID)

wait_for "$WORK/tunnel.log" "本地转发已就绪" 60 || fail "本地隧道未能监听"
if grep -qa "洞打通了" "$WORK/serve.log" "$WORK/tunnel.log"; then
    pass "打洞成功"
elif grep -qa "直连候选已准备" "$WORK/tunnel.log"; then
    pass "打洞未确认；已准备候选，随后验证实际业务"
else
    fail "既没有打洞成功，也没有候选直连建立证据"
fi

python3 - <<'PY' || fail "隧道转发数据不正确"
import socket, os, sys, concurrent.futures
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
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    results = list(pool.map(roundtrip, [blob] * 4))
assert results == [blob] * 4, "并发连接串包"
PY
pass "隧道转发正确（含 1MB 随机数据、多条并发连接）"
if [[ "$NATIVE_FAMILY" == "ipv6-only" ]]; then
    grep -qa 'family=IPv6' "$WORK/tunnel.log" || fail "实际已认证 winner 未报告 IPv6"
else
    grep -qa 'family=IPv4' "$WORK/tunnel.log" || fail "实际已认证 winner 未报告 IPv4"
fi
pass "实际业务使用已认证的 $NATIVE_FAMILY winner"
if [[ "$RELAY_MODE" == true ]]; then
    grep -qa 'path_kind="relay"' "$WORK/tunnel.log" || fail 'blackhole fallback did not select relay'
    grep -qa 'Relay UDP 已就绪' "$WORK/tunnel.log" || fail 'missing RelayReady diagnostic'
    pass 'direct blackholes → authenticated Relay winner'
fi

step "2.25 纯网络测速（不读写文件、不经过文件协议）"
RUST_LOG=info "$BIN" --key-file "$WORK/laptop.key" --log info speedtest \
    --signal 127.0.0.1:7000 "${DIRECT_OPTIONS[@]}" \
    --peer "$HOME_ID" \
    --duration 1 \
    --direction both \
    --block-size 65536 \
    --port 9103 --advertise "$(advertise_address 9103)" > "$WORK/speedtest.log" 2>&1 \
    || fail "speedtest 没有完成"
grep -Eq '^bytes:[[:space:]]+[1-9][0-9]*' "$WORK/speedtest.log" \
    || fail "speedtest 没有报告正数 bytes"
if find "$WORK/recv" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    fail "speedtest 不应在接收目录创建任何文件"
fi
pass "speedtest 成功，bytes > 0，接收目录保持为空"

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
    --signal 127.0.0.1:7000 "${DIRECT_OPTIONS[@]}" \
    --peer "$HOME_ID" \
    "$WORK/big.bin" --port 9105 --advertise "$(advertise_address 9105)" > "$WORK/push.log" 2>&1

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
    --signal 127.0.0.1:7000 "${DIRECT_OPTIONS[@]}" \
    --peer "$HOME_ID" \
    --listen 127.0.0.1:2223 \
    --to 127.0.0.1:9999 \
    --port 9106 --advertise "$(advertise_address 9106)" > "$WORK/tunnel2.log" 2>&1 &
PIDS+=($!)
wait_for "$WORK/tunnel2.log" "本地转发已就绪" 60 || fail "第二次本地隧道未能监听"

python3 - <<'PY' || fail "第二次隧道转发不正确"
import socket
s = socket.create_connection(("127.0.0.1", 2223), timeout=30)
s.sendall(b"round2")
assert s.recv(100) == b"round2"
s.close()
PY
pass "第二次连接同样成功（隔一段时间再连也能通）"

printf '\n\033[32m%s 全部通过\033[0m\n' "$NATIVE_FAMILY"

# The default invocation validates both native families. Public IPv6 is not required.
if [[ "$NATIVE_FAMILY" == "ipv4-only" && "$RELAY_MODE" == false ]]; then
    cleanup
    PIDS=()
    if python3 - <<'PYV6'
import socket, sys
try:
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
        probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        probe.bind(("::1", 0))
except OSError as exc:
    if exc.errno in (97, 99, 49, 47, 10047, 10049):
        print(f"SKIP IPv6 e2e: runner has no IPv6 capability: {exc}")
        sys.exit(42)
    raise
PYV6
    then
        if [[ "$PROFILE" == "release" ]]; then "$0" --ipv6 --release; else "$0" --ipv6; fi
    else
        probe_rc=$?
        [[ "$probe_rc" == 42 ]] || exit "$probe_rc"
    fi
    # Third deterministic fixture: real pairing/admission/QUIC, all direct candidates blackholed.
    if [[ "$PROFILE" == "release" ]]; then "$0" --relay --release; else "$0" --relay; fi
fi
