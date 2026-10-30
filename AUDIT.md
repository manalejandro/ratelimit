# Security & Bug Audit — ratelimit v1.0.0 → v1.1.0

Full review of the v1.0.0 source (`src/*.c`, `src/*.h`, `Makefile`), performed
2026-10-30. Every finding below was fixed in v1.1.0; regression tests live in
`scripts/run_tests.sh` (run via `make docker-test`).

Severity: **CRITICAL** (hang, memory corruption, DoS, data misdelivery),
**HIGH** (broken security feature, resource leak, wrong data),
**MEDIUM** (robustness, correctness in edge cases), **LOW** (hygiene).

---

## CRITICAL

### C1. Token-bucket deadlock: any rate < 64 kB/s could hang a connection forever
`proxy.c/fwd_thread` looped `while (!tb_consume(bucket, n))`. When a `recv()`
chunk `n` exceeded the bucket capacity (`rate × 4 kB`), tokens could *never*
reach `n` (they are capped at capacity), so `tb_consume` returned 0 forever.
E.g. `--rate 1` (capacity 4 kB) + a client sending 8 kB in one segment =
permanent hang, thread spinning through `nanosleep`.
**Fix:** (a) `tb_consume` admits an oversized chunk once when the bucket is
completely full, draining it; (b) the receive size is clamped to the bucket
capacity via `tb_chunk_hint()` so chunks are normally ≤ capacity;
(c) `tb_wait_ms` computes the wait against `min(cost, capacity)`.
**Test:** T05 (8 KiB through a 1 kB/s rule completes), T19.

### C2. Use-after-free on `SIGHUP` reload with in-flight connections
The reload path did `proxy_stop → proxy_destroy → config_init → config_load →
proxy_init` on the *same* stack objects, while detached forwarding threads
were still running. Those threads kept dereferencing:
- `c->sec` → `sec_destroy()` had already destroyed the rwlock;
- `c->mon` → monitor context `memset()` by the new `proxy_init`;
- `c->rule` → pointers into `cfg.rules[]`, wiped by `config_init`/reloaded;
- `proxy_start` could then re-`pthread_create` into `listener_t` slots whose
  old threads had been joined — but any *unjoined* TCP thread still touching
  the shared state was straight UB.
A reload under load could corrupt memory or crash the process.
**Fix:** all cross-thread state moved to a heap-allocated, refcounted
`proxy_shared_t` (sec ctx + monitor + stop flag + live-conn counter). Each
connection holds a reference; the structure is freed only after the last
connection drains. Connections copy everything they need from the rule
(`dst_host`, `dst_port`, `timeout`, `name`) at creation, so they never touch
`config_t` afterwards. Reload now validates the new config *before* tearing
anything down, and old connections are allowed to drain (true hot reload).
**Test:** T15 (established connection survives reload; new rules apply; old
listener disappears; invalid config ignored without dying).

### C3. UDP: unstable epoll pointers → replies to the wrong client / dead fds
`udp_session_t` entries lived in a flat array and `epoll.data.ptr` stored the
address of a *slot*. `close_udp_sess()` compacts the array by swapping the
last element into the removed slot — so a live session moved to a new address
while its epoll registration still pointed at the old slot. Subsequent events
dereferenced stale/reused memory: a reply could be `sendto()`’d to the wrong
client address (cross-client data leak), or hit a closed (and possibly
reused) relay fd.
**Fix:** sessions are heap nodes; the table stores *pointers*. Node addresses
are stable for their lifetime; swap-remove only moves pointers.
**Test:** T07, T08, T10 (multi-session UDP correctness under churn).

### C4. Signal race could hang shutdown forever
`while (g_running) pause();` — if `SIGTERM` arrived between the `g_running`
check and `pause()`, the handler ran first and `pause()` then blocked until
the *next* signal. Classic race; the process ignored Ctrl-C/TERM in a window.
**Fix:** signals (`SIGINT/SIGTERM/SIGHUP`) are blocked with
`pthread_sigmask` before any thread is created and consumed synchronously
with `sigwait()` in the main loop. No handlers, no race, no
async-signal-safety concerns.
**Test:** T15, T16 (deterministic prompt shutdown).

### C5. DNS + blocking `connect()` in the accept loop (DoS)
`spawn_tcp_conn()` ran `getaddrinfo()` and a blocking `connect()` *inside the
listener thread*. A dead/slow destination (or slow DNS) stalled the whole
rule for the kernel connect timeout (≈2 minutes); the accept backlog filled
and every client of that rule was cut off. One unreachable backend = full
rule outage.
**Fix:** each connection gets a setup thread that performs resolution and a
non-blocking `connect()` bounded by `poll()` to 5 s (`CONNECT_TIMEOUT`). The
listener only accepts and spawns. Accepted sockets are closed promptly when
the destination is unreachable.
**Test:** T18 (5 pending black-hole connects; healthy rule still serves in
< 3 s; black-holed client gets EOF ≈ connect timeout).

### C6. Uninitialised `pthread_t` joined / threads spawned on destroyed state
`proxy_start()` ignored `pthread_create()` failures, leaving `lst->thread`
uninitialised; `proxy_stop()` then called `pthread_join()` on it (UB). On the
reload-failure path, `proxy_stop` could also run when `proxy_init` had failed
early, and `monitor_stop()` joined a monitor thread that had never been
started. Additionally the "Reload failed – exiting" branch *did not exit* and
kept looping on a destroyed proxy (NULL/garbage derefs on the next signal).
**Fix:** per-listener and monitor `started` flags; joins only happen for
threads that exist; `pthread_create` failures are handled and logged; the
fatal reload path really exits.
**Test:** T15 (reload with invalid config keeps the process healthy).

### C7. UDP teardown loop leaked ~half the sessions
`for (i = 0; i < sess_count; i++) close_udp_sess(sessions, &sess_count, i, …)`
— `close_udp_sess` decrements `sess_count` and swaps, so the loop terminated
after ~n/2 iterations, leaking relay fds, token buckets and sec slots on
every stop/reload.
**Fix:** `while (sess_count > 0) close_udp_sess(…, 0, …)`.

---

## HIGH

### H1. Per-rule `max_connections` was silently ignored
`proxy_init` did `sec_init(&sec, global_max_conns / rule_count)` — the
documented per-rule limit (`-m`, `max_connections =`) never reached the
security layer, and the effective per-IP cap was a meaningless quotient
(8192/1 = 8192 by default).
**Fix:** `sec_allow(ctx, addr, rule->max_connections)` takes the limit per
call. **Test:** T13.

### H2. Auto-blacklist was unreachable dead code
`sec_allow` blacklisted when `conn_count >= max × 3`, but `conn_count` is
capped at `max` (increments stop there) — the condition could never fire.
The advertised "auto-blacklist after 3× limit" never happened.
**Fix:** a `rejects` counter increments on every limit rejection; after
`BLACKLIST_THRESHOLD` (3) consecutive rejections the IP is blacklisted for
300 s (counter decays once the client is back under the limit). The log now
includes the offending IP. **Test:** T13 (blacklist survives slot release).

### H3. Per-IP limit did not apply to UDP at all
The UDP path called `sec_allow()`/`sec_release()` *per packet*, so
`conn_count` oscillated 0→1→0 and no limit was ever enforced; one client
could occupy the entire 512-session table (and 512 relay sockets).
**Fix:** the sec slot is taken when a *session* is created and released when
it expires — sessions count as connections. **Test:** T08, T10.

### H4. `global_max_connections` was never enforced
Nothing counted total live connections.
**Fix:** `proxy_shared_t.live_conns` (TCP conns + UDP sessions) is checked
against `global_max_conns` before admission. **Test:** T14.

### H5. Idle timeout killed connections active in one direction
`SO_RCVTIMEO` was set per direction to the *full* rule timeout; a pure
download (traffic only server→client) was torn down after `timeout` seconds
because the client→server `recv()` timed out. `EINTR` on `recv()` also tore
the connection down.
**Fix:** 1-second recv ticks + a shared atomic `last_io` updated by both
directions; the connection is closed only when *neither* direction saw data
for `timeout` seconds. `EINTR` retries. The 1 s tick also bounds shutdown
latency. **Test:** T06 (idle closed; one-directional traffic kept alive).

### H6. Out-of-bounds read parsing `--name`
`memcpy(cur_name, optarg, sizeof cur_name - 1)` copied 63 bytes from the
argv string regardless of its length — an OOB read past the argument
(usually harmless, but UB and flagged by sanitizers).
**Fix:** `snprintf`. Same class of issue fixed in `config.c` section-header
parsing (`memcpy(section, line+1, 63)` copied uninitialised bytes into rule
names). **Tests:** T02, T09–T11.

### H7. Connection/counter leaks on spawn failure paths
In `spawn_tcp_conn`, `calloc`/`tb_init`/`malloc` failures closed fds but
never called `sec_release()` → the per-IP counter leaked upward until the IP
was permanently locked out. `mon_conn(+1)` was called *after* spawning the
threads, so a fast-finishing connection could decrement before the increment
(active-conn gauge stuck at 1 forever). `pthread_create` failure decremented
the refcount without releasing the connection (fd + memory leak).
**Fix:** counters are taken first and every failure path unwinds through a
single symmetric `conn_release()`. **Test:** T13 (limits stay accurate).

### H8. Half-close killed in-flight downloads
On EOF in one direction the old code set `active = 0` and shut everything
down — a client that sent a request, called `shutdown(SHUT_WR)` and waited
for a large response got a truncated body (common with HTTP clients, `nc`,
SMTP, etc.).
**Fix:** correct TCP half-close: EOF half-closes that direction (FIN towards
the peer) and the opposite direction keeps flowing until its own EOF/error/
idle timeout. **Test:** T19 (256 KiB response fully delivered after client
FIN through a 32 kB/s rule).

---

## MEDIUM

### M1. No input validation anywhere (`atoi`/`atof`)
`--rate 12abc` → 12, `--timeout -5`, `--interval 0` (division-like uses),
`--src host:80x` → 80 were all accepted silently; config values likewise.
**Fix:** strict `strtol`/`strtod` with full end-pointer and range checks for
every numeric option and config key; unknown `--unit`/`--proto` values are
errors instead of silent fallbacks; unknown config keys warn.
**Test:** T02 (17 invalid invocations rejected).

### M2. UDP relay ignored `send()` errors and shared one bucket
`send(relay_fd, …)` on a non-blocking socket could fail with `EAGAIN` — the
packet was lost but counted as *forwarded*. Both directions also shared a
single bucket, contradicting the documented independent up/down limiting.
**Fix:** failed sends count as drops; separate `up_bucket`/`down_bucket` per
session; queued ICMP errors (`ECONNREFUSED`) retire the session instead of
spinning the level-triggered epoll. **Test:** T08.

### M3. Wildcard binds were IPv6-only in practice
With an empty `src_host`, `getaddrinfo(NULL, …)` returns `::` first and the
socket was forced `IPV6_V6ONLY=1` → the rule listened on IPv6 only and was
unreachable on IPv4. **Fix:** wildcard binds create a dual-stack socket
(`IPV6_V6ONLY=0`) with automatic fallback to IPv4; an *explicit* host keeps
the requested family. **Test:** T17 (+ IPv4 tests throughout).

### M4. Accept loop hot-spun on fd exhaustion
`EMFILE/ENFILE/ENOBUFS/ENOMEM` fell through to a tight `accept()` loop
flooding the log. **Fix:** bounded back-off (100 ms) and `EINVAL` (socket
shutdown) exits the loop cleanly.

### M5. Blocking `send()` loop broke on `EINTR`
`if (w <= 0) goto done;` killed the connection when a signal interrupted
`send()`. **Fix:** `EINTR` retries; only real errors tear down.

### M6. No `TCP_NODELAY`, giant thread stacks
Proxied connections suffered Nagle + delayed-ACK latency, and each of the
two threads per connection reserved the default 8 MB stack (16 K threads ≈
128 GB of virtual memory reservations). **Fix:** `TCP_NODELAY` + keepalive on
both ends; 512 kB thread stacks; `SOCK_CLOEXEC`/`accept4` everywhere (fd
leak protection across `exec`).

### M7. Security table eviction could drop busy entries; no sweep for TCP-only setups
`evict_oldest()` ignored `conn_count` and could evict an IP with live
connections (limit accounting lost); `sec_cleanup()` was only called from
UDP listener threads, so TCP-only deployments never reaped stale entries.
**Fix:** eviction prefers connection-free entries; a stale sweep runs inline
when the table is full (any protocol), plus periodically from UDP loops.

### M8. Duplicate listeners silently split traffic
Two rules on the same `src host:port/proto` both bound successfully thanks to
`SO_REUSEPORT` and silently load-balanced clients between them. **Fix:**
duplicates are detected at config assembly time, warned about and skipped.
**Test:** T12.

### M9. Rate-limit sleep was unbounded
A single `nanosleep` could last `cost/refill` (64 kB chunk at 1 kB/s ≈ 64 s),
ignoring shutdown and peer teardown. **Fix:** sleeps are sliced to ≤100 ms
with `active`/`stop` checks between slices.

### M10. Reload failure lied about "keeping old state"
The old code destroyed the running proxy *before* loading the new config; if
the load failed, the log claimed the old state was kept while all listeners
were already closed. **Fix:** load+validate into a scratch config first; the
running proxy is untouched unless the new config is good (see C2).
**Test:** T15.

---

## LOW / hygiene

- `volatile int` used for cross-thread flags (`active`, `running`) — UB per
  C11; replaced with `atomic_int` throughout.
- Monitor active-conn counter could transiently go negative (fetch-sub then
  clamp); replaced with a CAS loop.
- Monitor thread `sleep(interval)` delayed `monitor_stop` by up to interval
  seconds; now sleeps in 200 ms slices and only joins if started.
- Config parser: CRLF files left a stray `\r` in values (fixed via
  `strcspn(line, "\r\n")`); `protocol`/`rate_unit` matching is now
  case-insensitive (`strcasecmp`) instead of exact `tcp/TCP` matches.
- `tb_init` return value was ignored for UDP sessions (uninitialised mutex
  on failure); now checked, and `tb_destroy` is safe on non-inited buckets.
- `Makefile`: no header dependency tracking (stale objects after header
  edits) → `-MMD -MP`; no `DESTDIR`/`PREFIX` → added (required for
  packaging); no hardening → `-fstack-protector-strong`,
  `-D_FORTIFY_SOURCE=2`, `-fPIE/-pie`, full RELRO (`-z relro -z now`),
  `-Wformat=2 -Wformat-security`.
- `config_save` did not check `fclose()` (silent truncation on ENOSPC).
- Version string centralised in `common.h` (`RATELIMIT_VERSION`) and kept in
  sync with `debian/changelog` by `scripts/build-deb.sh`.

---

## Threat-model notes (by design, not bugs)

- `SO_REUSEPORT` on listeners allows *another process of the same UID* to
  bind the same port and receive a share of the connections. This is the
  documented Linux behaviour and useful for multi-process scaling; operators
  who don't need it should ensure the binary runs under a dedicated account
  (the shipped systemd unit sandboxes the process and drops all capabilities
  except `CAP_NET_BIND_SERVICE`).
- Per-IP accounting is keyed by source IP only; clients behind NAT share a
  budget, and IP spoofing (UDP) can occupy session slots until TTL expiry.
  This is inherent to L3/L4 proxies; `max_connections`, the global cap and
  the blacklist bound the damage.
- The blacklist is in-memory and per-process (not shared across `SO_REUSEPORT`
  siblings, not persisted across restarts) — documented behaviour.

## Verification

- Clean build with `-Wall -Wextra -Wpedantic -Wshadow -Wformat=2
  -Wformat-security -D_FORTIFY_SOURCE=2`: **zero warnings**.
- `dpkg-buildpackage` + `lintian` inside `debian:bookworm` (Docker).
- Integration suite (`scripts/run_tests.sh`, 19 test groups / 40+ checks)
  runs against the **installed .deb** in a clean container: `make docker-test`.
