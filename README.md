# ratelimit

A bidirectional, multi-rule TCP/UDP rate-limiting proxy for IPv4 and IPv6.  
Place it in front of any service to enforce bandwidth limits at the connection level before traffic reaches your reverse proxy or application.

## Features

- **Multiple rules** – listen on several source host:port pairs simultaneously, each forwarding to its own destination
- **Port-range mapping** – `--src 0.0.0.0:8000-8009 --dst 10.0.0.1:9000-9009` expands into one rule per port pair
- **Dual-protocol** – TCP (stream, with correct half-close) and UDP (datagram) support
- **Dual-stack** – native IPv4 and IPv6 via `getaddrinfo`; IPv6 addresses use the `[addr]:port` notation; wildcard binds are dual-stack
- **Two rate-limiting modes** – `kbytes` (token bucket in bytes/s) or `packets` (token bucket in packets/s)
- **Bidirectional rate limiting** – upstream (client → server) and downstream (server → client) are throttled independently, for TCP *and* UDP
- **Real-time monitor** – live table of active connections, bytes, packets, and drops (enabled with `-v`)
- **Configuration file** – INI-style config file; downtime-free hot-reload on `SIGHUP` (established connections keep running, new connections follow the new config; an invalid file is rejected and changes nothing)
- **Security hardening** – per-rule/per-IP connection limits, automatic blacklisting of abusive IPs, global connection cap, idle-connection timeouts, bounded outbound connect timeouts, `SIGPIPE` suppression, hardened build (PIE, full RELRO, `FORTIFY_SOURCE`, stack protector)
- **Graceful shutdown** – `SIGTERM` / `SIGINT` stops listeners, gives in-flight connections a moment to finish, then exits
- **Debian package** – ready-to-build `.deb` with a sandboxed systemd unit and man page

## Requirements

- Linux (uses `epoll`, `accept4`, `SO_REUSEPORT`)  
- GCC ≥ 4.9 or Clang ≥ 3.5 with C11 support  
- pthreads (`-lpthread`)

## Build

```bash
make                       # builds ./ratelimit (hardened flags)
sudo make install          # installs to /usr/local/{bin,share/man}
make clean                 # removes build artefacts
```

### Debian package (.deb)

The package is built inside a clean `debian:bookworm` container — no build
dependencies needed on the host beyond Docker:

```bash
make docker-deb            # → dist/ratelimit_<version>_amd64.deb
sudo apt install ./dist/ratelimit_*.deb
```

(or natively: `dpkg-buildpackage -us -uc -b` with `debhelper` installed).

The package installs `/usr/bin/ratelimit`, the man page, a documented
default config at `/etc/ratelimit/ratelimit.conf` and a **disabled-by-default**
systemd unit:

```bash
sudoedit /etc/ratelimit/ratelimit.conf   # add your rules
sudo systemctl enable --now ratelimit
sudo systemctl reload ratelimit          # hot reload (SIGHUP)
```

### Integration tests (Docker)

```bash
make docker-test
```

Builds the `.deb`, installs it in a clean Debian container and runs the full
integration suite (`scripts/run_tests.sh`): forwarding integrity, rate
enforcement, dead-lock regressions, port ranges (TCP/UDP/config), per-IP
limits, blacklisting, global cap, `SIGHUP` reloads, half-close, IPv6,
black-hole destinations and shutdown timing.

## Quick Start

### Single rule – 512 kB/s TCP proxy

```bash
./ratelimit --src 0.0.0.0:8080 --dst 127.0.0.1:80 --rate 512 --unit kbytes
```

### Port range – map 8000-8009 to 9000-9009

```bash
./ratelimit --src 0.0.0.0:8000-8009 --dst 10.0.0.1:9000-9009 --rate 256 --name svc
```

Each pair becomes an independent rule (`svc-8000`, `svc-8001`, …) with its own
listener and rate limiter. Both ranges must span the same number of ports
(max 1024); alternatively the destination may be a single port shared by all
source ports. The same syntax works in the config file (`src_port = 8000-8009`).

### Multiple rules in one command

```bash
./ratelimit \
  --src 0.0.0.0:8080 --dst 10.0.0.1:80  --rate 1024 --unit kbytes --name web \
  --src 0.0.0.0:5353 --dst 10.0.0.1:53  --rate 500  --unit packets --proto udp --name dns \
  --src [::]:8443    --dst 10.0.0.1:443  --rate 2048 --unit kbytes  --name web-tls
```

### With real-time monitor

```bash
./ratelimit --src 0.0.0.0:8080 --dst 127.0.0.1:80 --rate 256 --verbose --interval 2
```

### Load from config file

```bash
./ratelimit --config ratelimit.conf --verbose
```

### Save current CLI rules to a config file

```bash
./ratelimit --src 0.0.0.0:3000-3009 --dst 127.0.0.1:4000-4009 --rate 256 --save-config my.conf
```

### Hot-reload config without downtime

```bash
kill -HUP $(pidof ratelimit)     # or: systemctl reload ratelimit
```

The new file is fully validated before anything is torn down; a broken config
is refused and the running state is kept.

## Configuration File

The config file uses an INI-like format.  A `[global]` section sets defaults and a `[ruleName]` section defines each forwarding rule. Ports accept single values or ranges.

```ini
# ratelimit.conf – example

[global]
verbose              = 0          # 1 = show live monitor
monitor_interval     = 1          # seconds between refreshes
global_max_connections = 8192     # hard cap: TCP connections + UDP sessions
log_level            = 2          # 0=ERR 1=WARN 2=INFO 3=DBG

[web]
src_host        = 0.0.0.0
src_port        = 8080
dst_host        = 127.0.0.1
dst_port        = 80
protocol        = tcp
rate            = 1024.00         # kB/s
rate_unit       = kbytes
max_connections = 200             # per source IP
timeout         = 60

[svc-range]
src_host        = 0.0.0.0
src_port        = 9000-9009       # expands to svc-range-9000 … svc-range-9009
dst_host        = 10.0.0.1
dst_port        = 8000-8009
protocol        = tcp
rate            = 256.00
rate_unit       = kbytes

[dns-udp]
src_host        = 0.0.0.0
src_port        = 5300
dst_host        = 8.8.8.8
dst_port        = 53
protocol        = udp
rate            = 1000.00
rate_unit       = packets
max_connections = 50              # concurrent UDP sessions per source IP
timeout         = 30

[ipv6-web]
src_host        = ::
src_port        = 8081
dst_host        = ::1
dst_port        = 80
protocol        = tcp
rate            = 512.00
rate_unit       = kbytes
max_connections = 100
timeout         = 60
```

## CLI Reference

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--src HOST:PORT[-PORT]` | `-s` | Listening address or range (repeatable) | – |
| `--dst HOST:PORT[-PORT]` | `-d` | Forwarding destination or range (paired with `--src`) | – |
| `--rate VALUE` | `-r` | Rate limit value | `1024` |
| `--unit kbytes\|packets` | `-u` | Rate unit | `kbytes` |
| `--proto tcp\|udp` | `-p` | Protocol | `tcp` |
| `--name NAME` | `-n` | Rule name (range rules get a `-<port>` suffix) | auto |
| `--config FILE` | `-c` | Load config file (enables `SIGHUP` reload) | – |
| `--save-config FILE` | `-S` | Write effective config to file and exit | – |
| `--verbose` | `-v` | Enable live monitor | off |
| `--interval SECS` | `-i` | Monitor refresh rate | `1` |
| `--max-conn N` | `-m` | Max connections per source IP (per rule) | `200` |
| `--timeout SECS` | `-t` | Idle connection timeout (0 disables) | `60` |
| `--log-level 0-3` | `-L` | Log verbosity | `2` |
| `--help` | `-h` | Show help | – |
| `--version` | `-V` | Show version | – |

`-r/-u/-p/-n/-m/-t` may appear before `--dst` (applies to the rule being
created) or after it (applies to the rule(s) just created, ranges included).
Command-line options take precedence over the config file.

## Architecture

```
Client ──────► [src_host:src_port]  listen socket
                        │
                   security check  ← per-IP connection limit + blacklist + global cap
                        │
                   setup thread    ← DNS + connect(dst) with 5 s timeout
                        │
                   fwd thread (up) ── token bucket ──────► [dst_host:dst_port]
                                                                │
                   fwd thread (down) ◄── token bucket ◄─────────┘
                        │
Client ◄───────────────┘
```

Each TCP connection is served by two lightweight threads (one per direction)
plus a setup phase that resolves and connects to the destination without ever
blocking the accept loop. UDP uses a single `epoll` loop per rule with a
per-client relay socket and stable heap-allocated session nodes. Shared
security/monitor state is refcounted, so reloads and shutdowns are safe while
connections drain.

### Rate Limiting

The **token bucket** algorithm is used for both directions:

- **`kbytes` mode** – bucket capacity = `rate × 4` kB; refills at `rate × 1024` bytes/s. Receive chunks are clamped to the bucket size, so even rates far below the socket buffer size are enforced smoothly (and can never deadlock). Excess TCP data waits (backpressure); excess UDP datagrams are dropped and counted.
- **`packets` mode** – same, but each datagram/chunk costs 1 token.

### Idle timeout

A connection is closed when **no data flowed in either direction** for
`timeout` seconds (default 60; `0` disables). One-directional traffic — e.g.
a long download — keeps the connection alive.

### Security

| Threat | Mitigation |
|--------|-----------|
| Connection flood | Per-source-IP connection counter, per rule (`max_connections`) |
| Persistent abusers | Auto-blacklist for 300 s after 3 consecutive rejections (logged with the IP) |
| Total resource exhaustion | `global_max_connections` caps TCP conns + UDP sessions |
| Dead/slow destination DoS | DNS + connect moved off the accept loop; 5 s connect timeout |
| Slow-read / Slowloris | Bidirectional idle timeout closes stale connections |
| Memory/fd exhaustion | Fixed session tables, 512 kB thread stacks, malloc failures handled, `SOCK_CLOEXEC` everywhere |
| Buffer overflow | Fixed 64 kB buffers; bounded string copies; strict input validation; `FORTIFY_SOURCE` build |
| Broken pipe | `SIGPIPE` ignored; `MSG_NOSIGNAL` on all `send` calls |
| Signal races | Synchronous `sigwait()` signal handling; deterministic shutdown |

## Signals

| Signal | Action |
|--------|--------|
| `SIGINT` / `SIGTERM` | Graceful shutdown (listeners stop, connections get ~1 s to finish) |
| `SIGHUP` | Validate + reload config file (requires `--config`); established connections are not dropped |

## Repository

<https://github.com/manalejandro/ratelimit>

## License

MIT License — see [LICENSE](LICENSE).
