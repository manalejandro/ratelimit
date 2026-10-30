#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# ratelimit integration test suite.
# Runs inside the Debian test container (docker/Dockerfile.test) against
# the binary INSTALLED from the .deb. Can also run on any Linux host with
# python3 + curl by invoking it directly.
#
# Exit code 0 → everything passed.
# ─────────────────────────────────────────────────────────────────────
set -u

RL="${RATELIMIT:-ratelimit}"
command -v "$RL" >/dev/null 2>&1 || RL=/usr/bin/ratelimit

WORK="$(mktemp -d /tmp/ratelimit-tests.XXXXXX)"
PIDS=()
PASS=0; FAIL=0
FAILED=()

log()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); log "  PASS: $1"; }
ko()   { FAIL=$((FAIL+1)); FAILED+=("$1"); log "  FAIL: $1${2:+ — $2}"; }
sect() { log; log "── $* ──────────────────────────────"; }
now_ms() { date +%s%3N; }

spawn() { "$@" >/dev/null 2>&1 & PIDS+=($!); }
spawn_log() { local f=$1; shift; "$@" >"$f" 2>&1 & PIDS+=($!); }

cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    sleep 0.3
    for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null; done
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

wait_port() { # wait_port PORT [up|down] [timeout_s]
    local port=$1 up=${2:-up} to=${3:-8} t0=$SECONDS
    while (( SECONDS - t0 < to )); do
        if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
            [[ $up == up ]] && return 0 || return 1
        else
            [[ $up == down ]] && return 0
        fi
        sleep 0.15
    done
    [[ $up == down ]]
}

rl_start() { # rl_start LOGFILE ARGS... ; waits for nothing (caller waits ports)
    local f=$1; shift
    spawn_log "$f" "$RL" "$@"
}

# ── backend helpers (python) ─────────────────────────────────────────
cat > "$WORK/echo_server.py" <<'PYEOF'
#!/usr/bin/env python3
"""TCP echo servers: first line sent is ECHO-<port>, then pure echo."""
import socketserver, sys, threading

class EH(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            self.wfile.write(("ECHO-%d\n" % self.server.server_address[1]).encode())
            while True:
                d = self.request.recv(65536)
                if not d: break
                self.wfile.write(d)
        except OSError:
            pass

class TS(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

for p in (int(x) for x in sys.argv[1:]):
    s = TS(("127.0.0.1", p), EH)
    threading.Thread(target=s.serve_forever, daemon=True).start()
threading.Event().wait()
PYEOF

cat > "$WORK/sink_server.py" <<'PYEOF'
#!/usr/bin/env python3
"""TCP sink: reads and discards everything, never replies."""
import socketserver, sys, threading

class H(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            d = self.request.recv(65536)
            if not d: break

class TS(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

for p in (int(x) for x in sys.argv[1:]):
    s = TS(("127.0.0.1", p), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
threading.Event().wait()
PYEOF

cat > "$WORK/udp_echo.py" <<'PYEOF'
#!/usr/bin/env python3
"""UDP echo: replies UECHO-<port>:<payload>."""
import socket, sys, threading

def serve(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    while True:
        d, a = s.recvfrom(65535)
        s.sendto(("UECHO-%d:" % port).encode() + d, a)

for p in (int(x) for x in sys.argv[1:]):
    threading.Thread(target=serve, args=(p,), daemon=True).start()
threading.Event().wait()
PYEOF

log "ratelimit integration tests"
log "binary: $RL ($($RL --version 2>&1))"
log "workdir: $WORK"

mkdir -p "$WORK/www"
head -c 4194304 /dev/urandom > "$WORK/www/big.bin"      # 4 MiB
head -c 16384    /dev/urandom > "$WORK/www/small.bin"    # 16 KiB
head -c 8192     /dev/urandom > "$WORK/www/tiny.bin"     # 8 KiB
SHA_BIG=$(sha256sum "$WORK/www/big.bin" | cut -d' ' -f1)
SHA_SMALL=$(sha256sum "$WORK/www/small.bin" | cut -d' ' -f1)
SHA_TINY=$(sha256sum "$WORK/www/tiny.bin" | cut -d' ' -f1)

spawn python3 "$WORK/echo_server.py" 21101 21102 21103 21104
spawn python3 "$WORK/sink_server.py" 21105
spawn python3 "$WORK/udp_echo.py" 21201 21202
spawn python3 -m http.server 21300 --bind 127.0.0.1 --directory "$WORK/www"
sleep 1

# ── T01: package / CLI sanity ────────────────────────────────────────
sect "T01 package + CLI sanity"
if dpkg -L ratelimit >/dev/null 2>&1; then
    for f in /usr/bin/ratelimit /etc/ratelimit/ratelimit.conf \
             /usr/share/man/man1/ratelimit.1.gz; do
        dpkg -L ratelimit | grep -qx "$f" && ok "deb ships $f" || ko "deb ships $f" "missing"
    done
    # systemd unit path differs: Debian → /lib/…, Ubuntu (usrmerge) → /usr/lib/…
    if dpkg -L ratelimit | grep -qE '^/(usr/)?lib/systemd/system/ratelimit\.service$'; then
        ok "deb ships the systemd unit"
    else
        ko "deb ships the systemd unit" "missing"
    fi
else
    log "  (dpkg not available – skipping package content checks)"
fi
"$RL" --version 2>&1 | grep -qE '^ratelimit [0-9]+\.[0-9]+\.[0-9]+$' \
    && ok "--version format" || ko "--version format"
"$RL" --help 2>&1 | grep -q -- '--src' && ok "--help mentions --src" || ko "--help"
"$RL" --help 2>&1 | grep -q -- 'PORT\[-PORT\]' && ok "--help documents port ranges" || ko "--help port ranges"

# ── T02: argument validation ─────────────────────────────────────────
sect "T02 argument validation (must all exit != 0)"
bad_args=(
    "-r abc -s 127.0.0.1:21400 -d 127.0.0.1:21101"
    "-r 0 -s 127.0.0.1:21400 -d 127.0.0.1:21101"
    "-r -5 -s 127.0.0.1:21400 -d 127.0.0.1:21101"
    "-s notahostport"
    "-s 127.0.0.1:0 -d 127.0.0.1:21101"
    "-s 127.0.0.1:65536 -d 127.0.0.1:21101"
    "-s 127.0.0.1:80x -d 127.0.0.1:21101"
    "-s 127.0.0.1:21400-21402 -d 127.0.0.1:21500-21501"
    "-s 127.0.0.1:20000-25000 -d 127.0.0.1:21101"
    "-d 127.0.0.1:21101"
    "-u bogus -s 127.0.0.1:21400 -d 127.0.0.1:21101"
    "-p sctp -s 127.0.0.1:21400 -d 127.0.0.1:21101"
    "-m 0 -s 127.0.0.1:21400 -d 127.0.0.1:21101"
    "-t -1 -s 127.0.0.1:21400 -d 127.0.0.1:21101"
    "-L 9 -s 127.0.0.1:21400 -d 127.0.0.1:21101"
    "-i 0 -s 127.0.0.1:21400 -d 127.0.0.1:21101"
    "-s 127.0.0.1:21400"
)
nbad=0
for a in "${bad_args[@]}"; do
    # shellcheck disable=SC2086
    if "$RL" $a >/dev/null 2>&1; then ko "rejects: $a" "exited 0"; else nbad=$((nbad+1)); fi
done
ok "$nbad/${#bad_args[@]} invalid invocations rejected"
[[ $nbad -eq ${#bad_args[@]} ]] || ko "some invalid invocations accepted"

# ── T03: TCP forwarding integrity (HTTP) ─────────────────────────────
sect "T03 TCP forwarding integrity"
rl_start "$WORK/rl-http.log" -s 127.0.0.1:21301 -d 127.0.0.1:21300 -r 8192 -L 1
wait_port 21301 || ko "T03 proxy did not start"
if curl -sf --max-time 20 -o "$WORK/small.out" "http://127.0.0.1:21301/small.bin"; then
    sha256sum "$WORK/small.out" | grep -q "$SHA_SMALL" \
        && ok "16 KiB file intact through proxy" || ko "16 KiB integrity"
else
    ko "16 KiB download through proxy"
fi
if curl -sf --max-time 60 -o "$WORK/big.out" "http://127.0.0.1:21301/big.bin"; then
    sha256sum "$WORK/big.out" | grep -q "$SHA_BIG" \
        && ok "4 MiB file intact through proxy" || ko "4 MiB integrity"
else
    ko "4 MiB download through proxy"
fi

# ── T04: TCP rate limiting ───────────────────────────────────────────
sect "T04 TCP rate limiting (4 MiB @ 512 kB/s)"
rl_start "$WORK/rl-rate.log" -s 127.0.0.1:21302 -d 127.0.0.1:21300 -r 512 -L 1
wait_port 21302 || ko "T04 proxy did not start"
t_direct=$(curl -sf --max-time 30 -o /dev/null -w '%{time_total}' "http://127.0.0.1:21300/big.bin")
t_limited=$(curl -sf --max-time 60 -o "$WORK/big2.out" -w '%{time_total}' "http://127.0.0.1:21302/big.bin")
sha256sum "$WORK/big2.out" | grep -q "$SHA_BIG" && ok "rate-limited payload intact" || ko "rate-limited payload"
log "  direct=${t_direct}s limited=${t_limited}s"
awk -v d="$t_direct" -v l="$t_limited" 'BEGIN{exit !(l >= 3.5)}' \
    && ok "throughput actually limited (>= 3.5 s for 4 MiB @ 512 kB/s)" \
    || ko "rate limiting ineffective" "4 MiB took only ${t_limited}s"
awk -v d="$t_direct" -v l="$t_limited" 'BEGIN{exit !(l > d)}' \
    && ok "limited slower than direct" || ko "limited slower than direct"

# ── T05: small rate must not hang (token-bucket regression) ──────────
sect "T05 tiny rate regression (8 KiB @ 1 kB/s, old code deadlocked)"
rl_start "$WORK/rl-tiny.log" -s 127.0.0.1:21303 -d 127.0.0.1:21300 -r 1 -L 1
wait_port 21303 || ko "T05 proxy did not start"
t0=$(now_ms)
if curl -sf --max-time 90 -o "$WORK/tiny.out" "http://127.0.0.1:21303/tiny.bin"; then
    t1=$(now_ms); dt=$(( (t1 - t0) ))
    sha256sum "$WORK/tiny.out" | grep -q "$SHA_TINY" \
        && ok "8 KiB @ 1 kB/s completed in ${dt} ms, payload intact" \
        || ko "tiny-rate payload corrupt"
    (( dt < 60000 )) && ok "no deadlock (< 60 s)" || ko "tiny-rate too slow" "${dt} ms"
else
    ko "8 KiB @ 1 kB/s never completed (deadlock regression)"
fi

# ── T06: idle timeout semantics ──────────────────────────────────────
sect "T06 idle timeout (kills idle, keeps one-directional traffic)"
rl_start "$WORK/rl-idle.log" -s 127.0.0.1:21304 -d 127.0.0.1:21101 -t 2 -r 4096 -L 1
wait_port 21304 || ko "T06 proxy did not start"
python3 - <<'PYEOF' && ok "idle connection closed by timeout" || ko "idle timeout"
import socket, time, sys
s = socket.create_connection(("127.0.0.1", 21304), 5)
s.settimeout(10)
s.recv(64)                      # banner
t0 = time.time()
d = s.recv(64)                  # proxy should close: EOF
dt = time.time() - t0
s.close()
sys.exit(0 if (d == b"" and 1.0 <= dt <= 6.0) else 1)
PYEOF
rl_start "$WORK/rl-sink.log" -s 127.0.0.1:21305 -d 127.0.0.1:21105 -t 3 -r 4096 -L 1
wait_port 21305 || ko "T06 sink proxy did not start"
python3 - <<'PYEOF' && ok "one-directional traffic keeps connection alive" || ko "one-directional keepalive"
import socket, time, sys
s = socket.create_connection(("127.0.0.1", 21305), 5)
s.settimeout(1.5)
try:
    for i in range(7):           # upstream data every 1 s, timeout is 3 s
        s.sendall(b"x")
        time.sleep(1)
    s.sendall(b"final")
    time.sleep(0.5)
    s.recv(1)                    # sink never replies → must TIME OUT, not EOF
    sys.exit(1)
except socket.timeout:
    sys.exit(0)                  # still open: correct
except OSError:
    sys.exit(1)                  # EOF/reset: old buggy behaviour
finally:
    s.close()
PYEOF

# ── T07: UDP relay ───────────────────────────────────────────────────
sect "T07 UDP relay"
rl_start "$WORK/rl-udp.log" -s 127.0.0.1:21211 -d 127.0.0.1:21201 -p udp -r 10000 -u packets -L 1
sleep 0.7
python3 - <<'PYEOF' && ok "UDP datagrams relayed and echoed" || ko "UDP relay"
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
got = 0
for i in range(10):
    s.sendto(b"ping%d" % i, ("127.0.0.1", 21211))
    d, _ = s.recvfrom(200)
    if d == b"UECHO-21201:ping%d" % i: got += 1
sys.exit(0 if got == 10 else 1)
PYEOF

# ── T08: UDP packet-rate drops ───────────────────────────────────────
sect "T08 UDP rate limiting (200 burst @ 20 pkt/s)"
rl_start "$WORK/rl-udpr.log" -s 127.0.0.1:21212 -d 127.0.0.1:21201 -p udp -r 20 -u packets -L 1
sleep 0.7
got=$(python3 - <<'PYEOF'
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.4)
for i in range(200):
    s.sendto(b"p%d" % i, ("127.0.0.1", 21212))
got = 0; t_end = time.time() + 3.0
while time.time() < t_end:
    try: s.recvfrom(300); got += 1
    except socket.timeout: pass
print(got)
PYEOF
)
log "  delivered: $got/200"
if [[ ${got:-0} -ge 30 && ${got:-0} -le 170 ]]; then
    ok "packet rate enforced (30 <= $got < 200)"
else
    ko "packet rate enforcement" "delivered=$got"
fi
UDPPID=${PIDS[-1]}
kill -0 "$UDPPID" 2>/dev/null && ok "proxy still alive after UDP storm" || ko "proxy died during UDP storm"

# ── T09: TCP port-range mapping ──────────────────────────────────────
sect "T09 TCP port range 21111-21113 -> 21101-21103"
rl_start "$WORK/rl-range.log" -s 127.0.0.1:21111-21113 -d 127.0.0.1:21101-21103 -r 4096 -n rng -L 1
for p in 21111 21112 21113; do wait_port $p || ko "T09 listener $p missing"; done
python3 - <<'PYEOF' && ok "each source port reaches its mapped destination" || ko "port-range mapping"
import socket, sys, time
rc = 0
for sport, dport in [(21111, 21101), (21112, 21102), (21113, 21103)]:
    s = socket.create_connection(("127.0.0.1", sport), 5); s.settimeout(3)
    banner = s.recv(64).decode().strip()
    s.sendall(b"data\n"); time.sleep(0.2)
    echo = s.recv(64)
    s.close()
    if banner != "ECHO-%d" % dport or echo != b"data\n":
        print("mismatch", sport, banner, echo); rc = 1
sys.exit(rc)
PYEOF

# ── T10: UDP port-range mapping ──────────────────────────────────────
sect "T10 UDP port range 21121-21122 -> 21201-21202"
rl_start "$WORK/rl-udprange.log" -s 127.0.0.1:21121-21122 -d 127.0.0.1:21201-21202 -p udp -r 5000 -u packets -L 1
sleep 0.7
python3 - <<'PYEOF' && ok "UDP range maps each port to its own backend" || ko "UDP port-range mapping"
import socket, sys
rc = 0
for sport, dport in [(21121, 21201), (21122, 21202)]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.sendto(b"hi", ("127.0.0.1", sport))
    d, _ = s.recvfrom(200)
    if d != ("UECHO-%d:hi" % dport).encode():
        print("mismatch", sport, d); rc = 1
sys.exit(rc)
PYEOF

# ── T11: config file with range + save roundtrip ─────────────────────
sect "T11 config file (ranges) + --save-config roundtrip"
cat > "$WORK/range.conf" <<'EOF'
[global]
log_level = 1

[svc]
src_host = 127.0.0.1
src_port = 21131-21132
dst_host = 127.0.0.1
dst_port = 21101-21102
protocol = tcp
rate = 4096
rate_unit = kbytes
max_connections = 50
timeout = 30
EOF
rl_start "$WORK/rl-conf.log" -c "$WORK/range.conf"
for p in 21131 21132; do wait_port $p || ko "T11 listener $p missing"; done
python3 - <<'PYEOF' && ok "config-file range rule works" || ko "config-file range"
import socket, sys
rc = 0
for sport, dport in [(21131, 21101), (21132, 21102)]:
    s = socket.create_connection(("127.0.0.1", sport), 5); s.settimeout(3)
    b = s.recv(64).decode().strip(); s.close()
    if b != "ECHO-%d" % dport: rc = 1
sys.exit(rc)
PYEOF
# save-config roundtrip: range expands to single-port sections;
# -r/-n AFTER --dst must apply to every expanded rule
"$RL" -s 127.0.0.1:21131-21132 -d 127.0.0.1:21101-21102 -r 100 -n sv -S "$WORK/saved.conf" >/dev/null 2>&1
nsec=$(grep -c '^\[' "$WORK/saved.conf")
nports=$(grep -cE '^src_port += 2113[12]$' "$WORK/saved.conf")
if [[ ${nsec:-0} -eq 3 && ${nports:-0} -eq 2 ]]; then
    ok "--save-config expands ranges (1 global + 2 rule sections)"
else
    ko "--save-config roundtrip" "sections=$nsec single-ports=$nports"
fi
grep -q '^\[sv-21131\]' "$WORK/saved.conf" && grep -q '^\[sv-21132\]' "$WORK/saved.conf" \
    && grep -qE '^rate += 100\.00$' "$WORK/saved.conf" \
    && ok "post-hoc -r/-n apply to every rule of a range" \
    || ko "post-hoc flags on ranges" "$(grep -E '^\[|^rate' "$WORK/saved.conf" | tr '\n' ' ')"
"$RL" -c "$WORK/saved.conf" -S "$WORK/saved2.conf" >/dev/null 2>&1 \
    && ok "saved config reloads cleanly" || ko "saved config reload"

# ── T12: duplicate listener detection ────────────────────────────────
sect "T12 duplicate rule detection"
# CLI: an exact duplicate pair is dropped with a warning (exit 0)
if "$RL" -s 127.0.0.1:21140 -d 127.0.0.1:21101 \
         -s 127.0.0.1:21140 -d 127.0.0.1:21102 -S "$WORK/dup.conf" >/dev/null 2>"$WORK/dup.err"; then
    ok "duplicate CLI pair tolerated with warning (exit 0)"
else
    ko "duplicate CLI pair" "non-zero exit"
fi
grep -qi "duplicate" "$WORK/dup.err" \
    && ok "duplicate reported in stderr" \
    || ko "duplicate stderr message" "$(head -2 "$WORK/dup.err" | tr '\n' ' ')"
nsec=$(grep -c '^\[' "$WORK/dup.conf" 2>/dev/null)
[[ ${nsec:-0} -eq 2 ]] && ok "saved config keeps one copy (global + rule)" \
                       || ko "dedup on save" "sections=${nsec:-0}"
# Config file: duplicate sections are skipped with a warning, rest still loads
cat > "$WORK/dup.conf" <<'EOF'
[global]
log_level = 1
[a]
src_host = 127.0.0.1
src_port = 21141
dst_host = 127.0.0.1
dst_port = 21101
[b]
src_host = 127.0.0.1
src_port = 21141
dst_host = 127.0.0.1
dst_port = 21102
EOF
out=$("$RL" -c "$WORK/dup.conf" -S "$WORK/dup2.conf" 2>/dev/null)
echo "$out" | grep -q "Loaded 1 rule" \
    && ok "config-file duplicates collapse to one rule" \
    || ko "config duplicate handling" "$(echo "$out" | head -1)"

# ── T13: per-IP max connections + auto blacklist ─────────────────────
sect "T13 max-conn per IP (2) + auto-blacklist after 3 rejects"
rl_start "$WORK/rl-mc.log" -s 127.0.0.1:21150 -d 127.0.0.1:21101 -m 2 -t 30 -r 4096 -L 1
wait_port 21150 || ko "T13 proxy did not start"
python3 - <<'PYEOF' && ok "limit + blacklist enforced, established conns survive" || ko "max-conn/blacklist"
import socket, sys, time

def conn(port, to=3):
    s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(to)
    return s

def alive(s):
    try:
        s.sendall(b"q\n"); time.sleep(0.2)
        d = s.recv(64)
        return d == b"q\n"
    except OSError:
        return False

def refused(port):
    try:
        s = conn(port)
    except OSError:
        return True          # kernel refused (listener gone) – count as refused
    time.sleep(0.3)
    try:
        d = s.recv(64)       # proxy accepts then immediately closes → b""
        s.close()
        return d == b""
    except socket.timeout:
        s.close()
        return False         # still open → NOT refused
    except OSError:
        return True

c1 = conn(21150); c1.recv(64)
c2 = conn(21150); c2.recv(64)
rc = 0
for i in range(3):           # 3 rejects → auto-blacklist (300 s)
    if not refused(21150): rc = 1
if not alive(c1) or not alive(c2): rc = 1   # established must survive
c1.close(); c2.close()
time.sleep(0.3)
# slots are free now, but the IP must still be blacklisted
if not refused(21150): rc = 1
sys.exit(rc)
PYEOF
grep -q "Auto-blacklisted" "$WORK/rl-mc.log" \
    && ok "blacklist event logged" || ko "blacklist logging" "no 'Auto-blacklisted' in log"

# ── T14: global connection cap ───────────────────────────────────────
sect "T14 global_max_connections cap"
cat > "$WORK/gcap.conf" <<'EOF'
[global]
global_max_connections = 2
log_level = 1
[g]
src_host = 127.0.0.1
src_port = 21155
dst_host = 127.0.0.1
dst_port = 21101
protocol = tcp
rate = 4096
max_connections = 100
timeout = 30
EOF
rl_start "$WORK/rl-gcap.log" -c "$WORK/gcap.conf"
wait_port 21155 || ko "T14 proxy did not start"
python3 - <<'PYEOF' && ok "global cap enforced" || ko "global cap"
import socket, sys, time
c1 = socket.create_connection(("127.0.0.1", 21155), 5); c1.settimeout(3); c1.recv(64)
c2 = socket.create_connection(("127.0.0.1", 21155), 5); c2.settimeout(3); c2.recv(64)
c3 = socket.create_connection(("127.0.0.1", 21155), 5); c3.settimeout(3)
time.sleep(0.3)
try:
    d = c3.recv(64)
    rc = 0 if d == b"" else 1
except socket.timeout:
    rc = 1
sys.exit(rc)
PYEOF
grep -q "Global connection limit" "$WORK/rl-gcap.log" \
    && ok "global-cap refusal logged" || ko "global-cap logging"

# ── T15: SIGHUP hot reload ───────────────────────────────────────────
sect "T15 SIGHUP reload (old conns drain, new config applies, bad config ignored)"
cat > "$WORK/reload.conf" <<'EOF'
[global]
log_level = 2
[a]
src_host = 127.0.0.1
src_port = 21160
dst_host = 127.0.0.1
dst_port = 21101
protocol = tcp
rate = 4096
timeout = 60
EOF
rl_start "$WORK/rl-reload.log" -c "$WORK/reload.conf"
wait_port 21160 || ko "T15 proxy did not start"
RLPID=${PIDS[-1]}
python3 - <<PYEOF && ok "reload keeps old conn, applies new rules, drops old listener" || ko "SIGHUP reload"
import socket, subprocess, sys, time, os, signal

old = socket.create_connection(("127.0.0.1", 21160), 5); old.settimeout(3)
assert old.recv(64).startswith(b"ECHO-21101"), "banner"

with open("$WORK/reload.conf", "w") as f:
    f.write("""[global]
log_level = 2
[b]
src_host = 127.0.0.1
src_port = 21161
dst_host = 127.0.0.1
dst_port = 21102
protocol = tcp
rate = 4096
timeout = 60
""")
os.kill($RLPID, signal.SIGHUP)
time.sleep(1.2)

rc = 0
old.sendall(b"still-here\n"); time.sleep(0.3)
if old.recv(64) != b"still-here\n": rc = 1          # old conn must survive
try:
    new = socket.create_connection(("127.0.0.1", 21161), 3); new.settimeout(3)
    if not new.recv(64).startswith(b"ECHO-21102"): rc = 1
except OSError:
    rc = 1                                            # new rule must be up
try:
    dead = socket.create_connection(("127.0.0.1", 21160), 2); dead.close()
    rc = 1                                            # old listener must be gone
except OSError:
    pass

# invalid config → keep serving
with open("$WORK/reload.conf", "w") as f:
    f.write("[b]\nsrc_port = 99999\nrate = -3\n")
os.kill($RLPID, signal.SIGHUP)
time.sleep(0.8)
try:
    new.sendall(b"after-bad\n"); time.sleep(0.3)
    if new.recv(64) != b"after-bad\n": rc = 1
except OSError:
    rc = 1
sys.exit(rc)
PYEOF
kill -0 "$RLPID" 2>/dev/null && ok "process alive after good+bad reloads" || ko "process died on reload"
grep -q "Reload aborted" "$WORK/rl-reload.log" && ok "bad config rejected in log" || ko "bad-config log message"
grep -q "Reload complete" "$WORK/rl-reload.log" && ok "reload completion logged" || ko "reload completion log"
kill -TERM "$RLPID" 2>/dev/null; wait "$RLPID" 2>/dev/null

# ── T16: graceful shutdown timing ────────────────────────────────────
sect "T16 SIGTERM graceful shutdown (<= 5 s, exit 0)"
rl_start "$WORK/rl-term.log" -s 127.0.0.1:21170 -d 127.0.0.1:21101 -r 4096 -L 1
wait_port 21170 || ko "T16 proxy did not start"
python3 - <<'PYEOF' &
import socket, time
s = socket.create_connection(("127.0.0.1", 21170), 5); s.settimeout(10)
time.sleep(8)   # hold a connection open across the SIGTERM
PYEOF
PIDS+=($!)
sleep 0.5
TPID=${PIDS[-2]}   # the ratelimit process (python helper pushed after)
t0=$(now_ms)
kill -TERM "$TPID" 2>/dev/null
if wait "$TPID" 2>/dev/null; then rc=0; else rc=$?; fi
t1=$(now_ms); dt=$(( t1 - t0 ))
log "  shutdown took ${dt} ms (rc=$rc)"
(( dt < 5000 )) && ok "shutdown under 5 s with an active connection" || ko "shutdown too slow" "${dt} ms"

# ── T17: IPv6 ────────────────────────────────────────────────────────
sect "T17 IPv6 [::1] listener"
cat > "$WORK/v6echo.py" <<'PYEOF'
import socket, threading
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::1", 21180)); s.listen(16)
def h(c):
    try:
        c.sendall(b"ECHO-V6\n")
        while True:
            d = c.recv(4096)
            if not d: break
            c.sendall(d)
    except OSError: pass
    finally: c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=h, args=(c,), daemon=True).start()
PYEOF
spawn python3 "$WORK/v6echo.py"
rl_start "$WORK/rl-v6.log" -s '[::1]:21181' -d '[::1]:21180' -r 4096 -L 1
python3 - <<'PYEOF' && ok "IPv6 proxying works" || ko "IPv6"
import socket, sys, time
s = None
for _ in range(40):                      # wait for listeners (max ~8 s)
    try:
        s = socket.create_connection(("::1", 21181), 2); break
    except OSError:
        time.sleep(0.2)
if s is None: sys.exit(1)
try:
    s.settimeout(3)
    b = s.recv(64)
    s.sendall(b"v6\n"); time.sleep(0.2)
    e = s.recv(64); s.close()
    sys.exit(0 if b == b"ECHO-V6\n" and e == b"v6\n" else 1)
except OSError as ex:
    print(ex); sys.exit(1)
PYEOF

# ── T18: dead destination must not stall other rules ─────────────────
sect "T18 dead destination (blackhole) does not stall listeners"
rl_start "$WORK/rl-bh.log" \
    -s 127.0.0.1:21190 -d 10.255.255.1:9 -r 4096 -n blackhole \
    -s 127.0.0.1:21191 -d 127.0.0.1:21101 -r 4096 -n healthy -L 1
wait_port 21190 || ko "T18 blackhole listener missing"
wait_port 21191 || ko "T18 healthy listener missing"
for i in 1 2 3 4 5; do
    (exec 3<>"/dev/tcp/127.0.0.1/21190"; sleep 10) 2>/dev/null &   # hold dead connects open
done
sleep 0.5
t0=$(now_ms)
python3 - <<'PYEOF'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", 21191), 5); s.settimeout(5)
assert s.recv(64).startswith(b"ECHO-21101")
s.sendall(b"fast\n"); time.sleep(0.2)
assert s.recv(64) == b"fast\n"
PYEOF
rc=$?
t1=$(now_ms); dt=$(( t1 - t0 ))
log "  healthy rule served in ${dt} ms while 5 connects to a blackhole were pending"
if [[ $rc -eq 0 && $dt -lt 3000 ]]; then
    ok "listener not blocked by dead destination"
else
    ko "dead destination stalled service" "rc=$rc dt=${dt}ms"
fi
python3 - <<'PYEOF' && ok "blackholed client connection is closed by the proxy" || ko "blackhole conn cleanup"
import socket, sys, time
s = socket.create_connection(("127.0.0.1", 21190), 5); s.settimeout(12)
t0 = time.time()
try:
    d = s.recv(64)          # proxy closes after its bounded connect timeout → EOF
    dt = time.time() - t0
    sys.exit(0 if d == b"" and dt <= 10 else 1)
except socket.timeout:
    sys.exit(1)             # never closed → blocking-connect regression
except ConnectionResetError:
    sys.exit(0)             # reset is also acceptable
finally:
    s.close()
PYEOF

# ── T19: TCP half-close (client SHUT_WR, download continues) ─────────
sect "T19 half-close: client FIN does not truncate the response"
rl_start "$WORK/rl-half.log" -s 127.0.0.1:21200 -d 127.0.0.1:21104 -r 32 -L 1
wait_port 21200 || ko "T19 proxy did not start"
python3 - <<'PYEOF' && ok "full 256 KiB response after client SHUT_WR" || ko "half-close truncation"
import socket, sys, time
s = socket.create_connection(("127.0.0.1", 21200), 5); s.settimeout(45)
banner = b""
while not banner.endswith(b"\n"):
    d = s.recv(64)
    if not d: break
    banner += d
payload = b"Z" * 262144
s.sendall(payload)
s.shutdown(socket.SHUT_WR)          # old code killed the download here
got = 0
while True:
    d = s.recv(65536)
    if not d: break
    got += len(d)
s.close()
sys.exit(0 if got == len(payload) else 1)
PYEOF

# ── T20: same source port for TCP and UDP ────────────────────────────
sect "T20 same port TCP+UDP (regression: dedup ran before post-hoc -p)"
rl_start "$WORK/rl-mixed.log" \
    -s 127.0.0.1:21450 -d 127.0.0.1:21101 -p tcp -n t53 \
    -s 127.0.0.1:21450 -d 127.0.0.1:21201 -p udp -n u53 -L 2
wait_port 21450 || ko "T20 TCP listener missing"
python3 - <<'PYEOF' && ok "CLI: TCP and UDP coexist on one port" || ko "CLI tcp+udp same port"
import socket, sys, time
rc = 0
try:
    s = socket.create_connection(("127.0.0.1", 21450), 5); s.settimeout(3)
    b = s.recv(64)
    s.sendall(b"tcp\n"); time.sleep(0.2)
    e = s.recv(64); s.close()
    if b != b"ECHO-21101\n" or e != b"tcp\n": rc = 1
except OSError as ex:
    print("tcp:", ex); rc = 1
try:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
    u.sendto(b"udp", ("127.0.0.1", 21450))
    d, _ = u.recvfrom(200)
    if d != b"UECHO-21201:udp": rc = 1
except OSError as ex:
    print("udp:", ex); rc = 1
sys.exit(rc)
PYEOF
grep -q "Loaded 2 rule" "$WORK/rl-mixed.log" \
    && ok "both rules loaded" || ko "rule count" "$(grep Loaded "$WORK/rl-mixed.log" | head -1)"
if grep -qi "duplicate" "$WORK/rl-mixed.log"; then
    ko "spurious duplicate warning" "$(grep -i duplicate "$WORK/rl-mixed.log" | head -1)"
else
    ok "no spurious duplicate warning"
fi

# range style: 3 TCP + 3 UDP on the same source ports (user's 6-warning case)
rl_start "$WORK/rl-mixedr.log" \
    -s 127.0.0.1:21460-21462 -d 127.0.0.1:21101-21103 -p tcp \
    -s 127.0.0.1:21460-21462 -d 127.0.0.1:21201 -p udp -L 2
sleep 0.8
grep -q "Loaded 6 rule" "$WORK/rl-mixedr.log" \
    && ok "ranges: 6 rules (3 tcp + 3 udp) on shared ports" \
    || ko "ranges rule count" "$(grep Loaded "$WORK/rl-mixedr.log" | head -1)"
python3 - <<'PYEOF' && ok "ranges: TCP mapping + UDP fan-in on same ports" || ko "ranges tcp+udp"
import socket, sys
rc = 0
for sport, dport in [(21460, 21101), (21461, 21102), (21462, 21103)]:
    try:
        s = socket.create_connection(("127.0.0.1", sport), 5); s.settimeout(3)
        if s.recv(64) != b"ECHO-%d\n" % dport: rc = 1
        s.close()
    except OSError:
        rc = 1
    try:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
        u.sendto(b"r", ("127.0.0.1", sport))
        d, _ = u.recvfrom(200)
        if d != b"UECHO-21201:r": rc = 1
    except OSError:
        rc = 1
sys.exit(rc)
PYEOF

# config-file style: two sections, same src_port, different protocols
cat > "$WORK/mixed.conf" <<'EOF'
[global]
log_level = 2
[dns-t]
src_host = 127.0.0.1
src_port = 21470
dst_host = 127.0.0.1
dst_port = 21101
protocol = tcp
rate = 4096
[dns-u]
src_host = 127.0.0.1
src_port = 21470
dst_host = 127.0.0.1
dst_port = 21201
protocol = udp
rate = 4096
rate_unit = packets
EOF
rl_start "$WORK/rl-mixedc.log" -c "$WORK/mixed.conf"
sleep 0.8
grep -q "Loaded 2 rule" "$WORK/rl-mixedc.log" \
    && ok "config: tcp+udp sections on same port both load" \
    || ko "config tcp+udp" "$(grep Loaded "$WORK/rl-mixedc.log" | head -1)"
python3 - <<'PYEOF' && ok "config: both protocols relay on the shared port" || ko "config tcp+udp relay"
import socket, sys, time
rc = 0
try:
    s = socket.create_connection(("127.0.0.1", 21470), 5); s.settimeout(3)
    if s.recv(64) != b"ECHO-21101\n": rc = 1
    s.close()
except OSError:
    rc = 1
try:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
    u.sendto(b"c", ("127.0.0.1", 21470))
    d, _ = u.recvfrom(200)
    if d != b"UECHO-21201:c": rc = 1
except OSError:
    rc = 1
sys.exit(rc)
PYEOF

# ── summary ──────────────────────────────────────────────────────────
sect "SUMMARY"
log "  passed: $PASS"
log "  failed: $FAIL"
if (( FAIL > 0 )); then
    log "  failed checks:"
    for f in "${FAILED[@]}"; do log "    - $f"; done
    exit 1
fi
log "ALL TESTS PASSED"
exit 0
