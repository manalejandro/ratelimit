# ratelimit

A bidirectional, multi-rule TCP/UDP rate-limiting proxy for IPv4 and IPv6.  
Place it in front of any service to enforce bandwidth limits at the connection level before traffic reaches your reverse proxy or application.

## Features

- **Multiple rules** – listen on several source host:port pairs simultaneously, each forwarding to its own destination
- **Dual-protocol** – TCP (stream) and UDP (datagram) support
- **Dual-stack** – native IPv4 and IPv6 via `getaddrinfo`; IPv6 addresses use the `[addr]:port` notation
- **Two rate-limiting modes** – `kbytes` (token bucket in bytes/s) or `packets` (token bucket in packets/s)
- **Bidirectional rate limiting** – both upstream (client → server) and downstream (server → client) are independently throttled
- **Real-time monitor** – live table of active connections, bytes, packets, and drops (enabled with `-v`)
- **Configuration file** – INI-style config file; hot-reload on `SIGHUP`
- **Security hardening** – per-IP connection limits, automatic blacklisting of abusive IPs, idle-connection timeouts, `SIGPIPE` suppression
- **Graceful shutdown** – `SIGTERM` / `SIGINT` cleanly stops all listeners and in-flight connections

## Requirements

- Linux (uses `epoll`, `SO_REUSEPORT`)  
- GCC ≥ 4.9 or Clang ≥ 3.5 with C11 support  
- pthreads (`-lpthread`)

## Build

```bash
make          # builds ./ratelimit
make install  # copies to /usr/local/bin/ratelimit
make clean    # removes build artefacts
```

## Quick Start

### Single rule – 512 kB/s TCP proxy

```bash
./ratelimit --src 0.0.0.0:8080 --dst 127.0.0.1:80 --rate 512 --unit kbytes
```

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
./ratelimit --src 0.0.0.0:3000 --dst 127.0.0.1:3001 --rate 256 --save-config my.conf
```

### Hot-reload config without downtime

```bash
kill -HUP $(pidof ratelimit)
```

## Configuration File

The config file uses an INI-like format.  A `[global]` section sets defaults and a `[ruleName]` section defines each forwarding rule.

```ini
# ratelimit.conf – example

[global]
verbose              = 0          # 1 = show live monitor
monitor_interval     = 1          # seconds between refreshes
global_max_connections = 8192
log_level            = 2          # 0=ERR 1=WARN 2=INFO 3=DBG

[web]
src_host        = 0.0.0.0
src_port        = 8080
dst_host        = 127.0.0.1
dst_port        = 80
protocol        = tcp
rate            = 1024.00         # kB/s
rate_unit       = kbytes
max_connections = 200
timeout         = 60

[dns-udp]
src_host        = 0.0.0.0
src_port        = 5300
dst_host        = 8.8.8.8
dst_port        = 53
protocol        = udp
rate            = 1000.00
rate_unit       = packets
max_connections = 50
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
| `--src HOST:PORT` | `-s` | Listening address (repeatable) | – |
| `--dst HOST:PORT` | `-d` | Forwarding destination (paired with `--src`) | – |
| `--rate VALUE` | `-r` | Rate limit value | `1024` |
| `--unit kbytes\|packets` | `-u` | Rate unit | `kbytes` |
| `--proto tcp\|udp` | `-p` | Protocol | `tcp` |
| `--name NAME` | `-n` | Rule name for the last `--src`/`--dst` pair | auto |
| `--config FILE` | `-c` | Load config file | – |
| `--save-config FILE` | `-S` | Write config to file and exit | – |
| `--verbose` | `-v` | Enable live monitor | off |
| `--interval SECS` | `-i` | Monitor refresh rate | `1` |
| `--max-conn N` | `-m` | Max connections per source IP | `200` |
| `--timeout SECS` | `-t` | Idle connection timeout | `60` |
| `--log-level 0-3` | `-L` | Log verbosity | `2` |
| `--help` | `-h` | Show help | – |
| `--version` | `-V` | Show version | – |

## Architecture

```
Client ──────► [src_host:src_port]  listen socket
                       │
                  security check  ← per-IP connection limit + blacklist
                       │
                  token bucket    ← rate limiting (upstream)
                       │
                  fwd_thread_up ──────────────────► [dst_host:dst_port]
                                                          │
                  fwd_thread_down ◄──── token bucket ◄───┘  (downstream)
                       │
Client ◄───────────────┘
```

Each TCP connection spawns two lightweight threads (one per direction).  
UDP uses a single `epoll` loop per rule with a per-client relay socket table.

### Rate Limiting

The **token bucket** algorithm is used for both directions:

- **`kbytes` mode** – bucket capacity = `rate × 4` kB; refills at `rate × 1024` bytes/s.  Excess data waits (TCP backpressure) or is dropped (UDP).
- **`packets` mode** – same but cost = 1 token per datagram/chunk.

### Security

| Threat | Mitigation |
|--------|-----------|
| Connection flood | Per-IP connection counter; hard limit per rule |
| Persistent abusers | Auto-blacklist (300 s) after 3× limit |
| Slow-read / Slowloris | Idle timeout closes stale connections |
| Resource exhaustion | Fixed session table size; malloc failures handled |
| Buffer overflow | Fixed 64 kB buffers; all lengths checked before `send`/`recv` |
| Broken pipe | `SIGPIPE` ignored; `MSG_NOSIGNAL` on all `send` calls |

## Signals

| Signal | Action |
|--------|--------|
| `SIGINT` / `SIGTERM` | Graceful shutdown |
| `SIGHUP` | Reload config file (requires `--config`) |

## Repository

<https://github.com/manalejandro/ratelimit>

## License

MIT License — see [LICENSE](LICENSE).
