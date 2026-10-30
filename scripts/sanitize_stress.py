#!/usr/bin/env python3
"""Stress scenario for sanitizer builds: reload under load + fast shutdown.

Usage: sanitize_stress.py /path/to/ratelimit
Exits 0 if no sanitizer report appears in the proxy output and all phases
complete; exits 1 otherwise.
"""
import os, random, signal, socket, subprocess, sys, tempfile, threading, time

RL = sys.argv[1]
WORK = tempfile.mkdtemp(prefix="rl-san-")

# ── echo backend ─────────────────────────────────────────────────────
import socketserver
class EH(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            while True:
                d = self.request.recv(65536)
                if not d: break
                self.wfile.write(d)
        except OSError:
            pass
class TS(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
srvA = TS(("127.0.0.1", 22001), EH)
srvB = TS(("127.0.0.1", 22002), EH)
threading.Thread(target=srvA.serve_forever, daemon=True).start()
threading.Thread(target=srvB.serve_forever, daemon=True).start()

CONF_A = os.path.join(WORK, "a.conf")
CONF_B = os.path.join(WORK, "b.conf")

def write_conf(path, src, dst):
    with open(path, "w") as f:
        f.write(f"""[global]
log_level = 2
global_max_connections = 512
[r]
src_host = 127.0.0.1
src_port = {src}
dst_host = 127.0.0.1
dst_port = {dst}
protocol = tcp
rate = 64
rate_unit = kbytes
max_connections = 64
timeout = 30
""")

write_conf(CONF_A, 22010, 22001)
write_conf(CONF_B, 22011, 22002)
os.symlink(CONF_A, os.path.join(WORK, "live.conf"))

env = dict(os.environ)
env["ASAN_OPTIONS"] = "detect_leaks=1:abort_on_error=0"
env["TSAN_OPTIONS"] = "halt_on_error=0"
log = open(os.path.join(WORK, "proxy.log"), "w+")
p = subprocess.Popen([RL, "-c", os.path.join(WORK, "live.conf")],
                     stdout=log, stderr=subprocess.STDOUT, env=env)

def wait_port(port, timeout=10):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s = socket.create_connection(("127.0.0.1", port), 0.5)
            s.close(); return True
        except OSError:
            time.sleep(0.1)
    return False

assert wait_port(22010), "proxy did not start"

# ── load generator: continuous short connections + data ───────────────
stop = threading.Event()
errors = []
def client(port):
    while not stop.is_set():
        try:
            s = socket.create_connection(("127.0.0.1", port), 1)
            s.settimeout(2)
            payload = os.urandom(random.randint(1024, 60000))
            s.sendall(payload)
            got = b""
            while len(got) < len(payload):
                d = s.recv(65536)
                if not d: break
                got += d
            s.close()
            if got != payload:
                errors.append(f"echo mismatch on {port}: {len(got)}/{len(payload)}")
        except OSError:
            pass  # proxy may be mid-reload; connection refused is fine
        time.sleep(0.01)

threads = [threading.Thread(target=client, args=(22010,), daemon=True) for _ in range(8)]
threads += [threading.Thread(target=client, args=(22011,), daemon=True) for _ in range(8)]
for t in threads: t.start()

# ── reload storm: flip configs while traffic flows ───────────────────
live = os.path.join(WORK, "live.conf")
for i in range(8):
    time.sleep(0.7)
    target = CONF_B if i % 2 == 0 else CONF_A
    write_conf(target, 22011 if i % 2 == 0 else 22010,
               22002 if i % 2 == 0 else 22001)
    os.replace(target, live)
    p.send_signal(signal.SIGHUP)
    if p.poll() is not None:
        print(f"PROXY DIED on reload #{i}", file=sys.stderr); break

# one bad-config reload in the middle of the storm
with open(live, "w") as f:
    f.write("[r]\nsrc_port = 99999\nrate = -1\n")
p.send_signal(signal.SIGHUP)
time.sleep(0.5)
assert p.poll() is None, "proxy died on bad-config reload"

# restore a good config for the shutdown phase
write_conf(CONF_A, 22010, 22001)
os.replace(CONF_A, live)
p.send_signal(signal.SIGHUP)
time.sleep(0.8)
assert p.poll() is None, "proxy died on final reload"

# ── shutdown under load ──────────────────────────────────────────────
t0 = time.time()
p.send_signal(signal.SIGTERM)
rc = p.wait(15)
dt = time.time() - t0
stop.set()
time.sleep(0.3)

log.seek(0)
out = log.read()
bad = [ln for ln in out.splitlines() if
       any(k in ln for k in ("ERROR:", "SUMMARY:", "WARNING: ThreadSanitizer",
                             "runtime error", "LeakSanitizer", "data race"))]

print(f"exit={rc} shutdown={dt:.2f}s echo_errors={len(errors)} sanitizer_lines={len(bad)}")
for ln in bad[:40]:
    print("SANITIZER:", ln)
for e in errors[:5]:
    print("ECHO:", e)

ok = rc == 0 and dt < 8 and not bad and not errors
print("RESULT:", "CLEAN" if ok else "DIRTY")
sys.exit(0 if ok else 1)
