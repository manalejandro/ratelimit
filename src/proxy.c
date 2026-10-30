#include "proxy.h"

/* ─────────────────────────────────────────────────────────────
 * Shared context (heap, refcounted)
 *
 * Detached forwarding threads may outlive proxy_destroy() (SIGHUP
 * reload, shutdown while connections drain).  Every connection holds
 * a reference, so sec/monitor state is freed only after the last
 * connection is gone – no use-after-free on reload.
 * ───────────────────────────────────────────────────────────── */

static proxy_shared_t *sh_acquire(proxy_shared_t *sh)
{
    atomic_fetch_add(&sh->refcount, 1);
    return sh;
}

static void sh_release(proxy_shared_t *sh)
{
    if (atomic_fetch_sub(&sh->refcount, 1) != 1) return;
    sec_destroy(&sh->sec);
    free(sh);
}

/* ─────────────────────────────────────────────────────────────
 * Socket helpers
 * ───────────────────────────────────────────────────────────── */

static int make_listen_socket(const rule_t *r)
{
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = (r->protocol == PROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;
    hints.ai_flags    = AI_PASSIVE;

    char port[8];
    snprintf(port, sizeof port, "%d", r->src_port);
    int wildcard   = (r->src_host[0] == '\0');
    const char *host = wildcard ? NULL : r->src_host;

    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc) { LOG(LOG_ERR, "getaddrinfo(%s:%d): %s", host ? host : "*", r->src_port, gai_strerror(rc)); return -1; }

    int fd = -1, last_err = 0;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol);
        if (fd < 0) { last_err = errno; continue; }

        int on = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);
        if (r->protocol == PROTO_TCP)
            setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
        if (rp->ai_family == AF_INET6) {
            /*
             * Wildcard host → dual-stack socket (serves IPv4 too).
             * Explicit host → IPv6-only, as requested.
             * (The old code forced V6ONLY=1 always, so `--src :8080`
             * silently listened on IPv6 only.)
             */
            int v6only = wildcard ? 0 : 1;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof v6only);
        }

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        last_err = errno;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        LOG(LOG_ERR, "bind(%s:%d): %s", host ? host : "*", r->src_port,
            strerror(last_err ? last_err : ENOENT));
        return -1;
    }

    if (r->protocol == PROTO_TCP && listen(fd, SOMAXCONN) < 0) {
        LOG(LOG_ERR, "listen: %s", strerror(errno));
        close(fd); return -1;
    }
    return fd;
}

/*
 * Resolve + connect with a bounded timeout.  For TCP the connect is
 * non-blocking + poll so a black-holed destination cannot stall the
 * caller for the kernel default (~2 minutes).
 */
static int connect_with_timeout(const char *host, int port,
                                protocol_t proto, int timeout_s)
{
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = (proto == PROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;

    char portbuf[8];
    snprintf(portbuf, sizeof portbuf, "%d", port);

    int rc = getaddrinfo(host, portbuf, &hints, &res);
    if (rc) { LOG(LOG_ERR, "getaddrinfo(%s:%d): %s", host, port, gai_strerror(rc)); return -1; }

    if (timeout_s <= 0) timeout_s = CONNECT_TIMEOUT;

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol);
        if (fd < 0) continue;

        if (proto == PROTO_TCP) {
            int on = 1;
            setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);

            set_nonblocking(fd);
            int crc = connect(fd, rp->ai_addr, rp->ai_addrlen);
            if (crc < 0 && errno == EINPROGRESS) {
                struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
                int prc = poll(&pfd, 1, timeout_s * 1000);
                if (prc <= 0) {
                    close(fd); fd = -1; errno = ETIMEDOUT; continue;
                }
                int err = 0; socklen_t el = sizeof err;
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
                if (err != 0) { close(fd); fd = -1; errno = err; continue; }
            } else if (crc < 0) {
                close(fd); fd = -1; continue;
            }
            clear_nonblocking(fd);
        } else {
            if (connect(fd, rp->ai_addr, rp->ai_addrlen) < 0) {
                close(fd); fd = -1; continue;
            }
        }
        break;
    }
    freeaddrinfo(res);
    return fd;
}

/* ─────────────────────────────────────────────────────────────
 * TCP – bidirectional forwarding
 * ───────────────────────────────────────────────────────────── */

typedef struct {
    tcp_conn_t *conn;
    int         upstream;   /* 1 = client→server, 0 = server→client */
} fwd_arg_t;

static void conn_release(tcp_conn_t *c)
{
    /* last thread to exit cleans up */
    if (atomic_fetch_sub(&c->refcount, 1) != 1) return;

    close(c->client_fd);
    if (c->server_fd >= 0) close(c->server_fd);
    if (c->sec_held) sec_release(&c->sh->sec, &c->client_addr);
    mon_conn(&c->sh->mon, c->rule_idx, 0);
    atomic_fetch_sub(&c->sh->live_conns, 1);
    tb_destroy(&c->up_bucket);
    tb_destroy(&c->down_bucket);
    sh_release(c->sh);
    free(c);
}

static void run_direction(tcp_conn_t *c, int upstream)
{
    int src = upstream ? c->client_fd : c->server_fd;
    int dst = upstream ? c->server_fd : c->client_fd;
    token_bucket_t *bucket = upstream ? &c->up_bucket : &c->down_bucket;

    char *buf = malloc(BUFFER_SIZE);
    if (!buf) {
        atomic_store(&c->active, 0);
        conn_release(c);
        return;
    }

    /* 1-second recv tick: bounds shutdown latency and drives the
     * bidirectional idle timeout (the old code used SO_RCVTIMEO with
     * the full rule timeout per direction, which killed connections
     * that were only active in the other direction). */
    struct timeval tick = { 1, 0 };
    setsockopt(src, SOL_SOCKET, SO_RCVTIMEO, &tick, sizeof tick);

    size_t chunk = tb_chunk_hint(bucket);

    while (atomic_load(&c->active) && !atomic_load(&c->sh->stop)) {
        ssize_t n = recv(src, buf, chunk, 0);
        if (n > 0) {
            atomic_store(&c->last_io, (long)time(NULL));

            /* ── rate limiting with backpressure ──
             * Sleeps in ≤100 ms slices so stop/active are noticed fast. */
            while (!tb_consume(bucket, (size_t)n)) {
                if (!atomic_load(&c->active) || atomic_load(&c->sh->stop))
                    goto done;
                double ms = tb_wait_ms(bucket, (size_t)n);
                if (ms < 1.0)   ms = 1.0;
                if (ms > 100.0) ms = 100.0;
                struct timespec ts = {
                    (time_t)(ms / 1000.0),
                    (long)(fmod(ms, 1000.0) * 1e6)
                };
                nanosleep(&ts, NULL);
            }
            if (atomic_load(&c->sh->stop)) goto done;

            /* ── full write (EINTR-safe) ── */
            ssize_t sent = 0;
            while (sent < n) {
                ssize_t w = send(dst, buf + sent, (size_t)(n - sent), MSG_NOSIGNAL);
                if (w > 0) { sent += w; continue; }
                if (w < 0 && errno == EINTR) continue;
                goto done;   /* peer gone – tear down both directions */
            }

            if (upstream) {
                mon_bytes(&c->sh->mon, c->rule_idx, (long)n, 0);
                mon_pkts (&c->sh->mon, c->rule_idx, 1,       0);
            } else {
                mon_bytes(&c->sh->mon, c->rule_idx, 0, (long)n);
                mon_pkts (&c->sh->mon, c->rule_idx, 0, 1);
            }
            continue;
        }

        if (n == 0) {
            /*
             * EOF: half-close this direction (FIN towards dst) and let
             * the opposite direction finish naturally – correct TCP
             * proxy semantics for protocols that shutdown(SHUT_WR)
             * before reading the response.
             */
            shutdown(src, SHUT_RD);
            shutdown(dst, SHUT_WR);
            goto quiet;
        }

        /* n < 0 */
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* recv tick – enforce the idle timeout on BOTH directions */
            if (c->timeout > 0 &&
                (long)time(NULL) - atomic_load(&c->last_io) >= c->timeout) {
                LOG(LOG_DEBUG, "[%s] idle timeout (%d s), closing",
                    c->name, c->timeout);
                goto done;
            }
            continue;
        }
        goto done;   /* real socket error */
    }
    goto quiet;   /* active cleared by peer thread, or global stop */

done:
    atomic_store(&c->active, 0);
    shutdown(c->client_fd, SHUT_RDWR);
    if (c->server_fd >= 0) shutdown(c->server_fd, SHUT_RDWR);
quiet:
    free(buf);
    conn_release(c);
}

static void *fwd_thread(void *arg)
{
    fwd_arg_t *fa = (fwd_arg_t *)arg;
    tcp_conn_t *c = fa->conn;
    int upstream  = fa->upstream;
    free(fa);
    run_direction(c, upstream);
    return NULL;
}

/* Setup thread: resolves + connects to the destination, spawns the
 * downstream thread, then serves the upstream direction itself.
 * DNS lookups and connects therefore never block the accept loop. */
static void *tcp_conn_thread(void *arg)
{
    tcp_conn_t *c = (tcp_conn_t *)arg;

    int sfd = connect_with_timeout(c->dst_host, c->dst_port,
                                   PROTO_TCP, CONNECT_TIMEOUT);
    if (sfd < 0) {
        LOG(LOG_WARN, "[%s] cannot connect to %s:%d (%s)", c->name,
            c->dst_host, c->dst_port, strerror(errno));
        atomic_store(&c->active, 0);
        conn_release(c);
        return NULL;
    }
    c->server_fd = sfd;

    atomic_fetch_add(&c->refcount, 1);   /* reference for downstream */
    fwd_arg_t *dn = malloc(sizeof *dn);
    int spawned = 0;
    if (dn) {
        dn->conn = c; dn->upstream = 0;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_attr_setstacksize(&attr, FWD_THREAD_STACK);
        pthread_t t;
        spawned = (pthread_create(&t, &attr, fwd_thread, dn) == 0);
        pthread_attr_destroy(&attr);
        if (!spawned) free(dn);
    }
    if (!spawned) {
        LOG(LOG_ERR, "[%s] cannot spawn downstream thread", c->name);
        atomic_store(&c->active, 0);
        conn_release(c);   /* drop the downstream reference */
        conn_release(c);   /* drop ours – triggers cleanup */
        return NULL;
    }

    run_direction(c, 1);
    return NULL;
}

static void spawn_tcp_conn(listener_t *lst, int client_fd,
                           const struct sockaddr_storage *caddr)
{
    proxy_shared_t *sh = lst->sh;
    const rule_t *rule = lst->rule;

    if (atomic_load(&sh->stop) || !atomic_load(&lst->running)) {
        close(client_fd);
        return;
    }
    if (atomic_load(&sh->live_conns) >= sh->global_max_conns) {
        LOG(LOG_WARN, "Global connection limit (%d) reached, refusing",
            sh->global_max_conns);
        close(client_fd);
        return;
    }
    if (!sec_allow(&sh->sec, caddr, rule->max_connections)) {
        char ipbuf[INET6_ADDRSTRLEN];
        LOG(LOG_WARN, "Blocked connection from %s (per-IP limit or blacklist)",
            sa_str(caddr, ipbuf, sizeof ipbuf));
        close(client_fd);
        return;
    }

    tcp_conn_t *c = calloc(1, sizeof *c);
    if (!c) { sec_release(&sh->sec, caddr); close(client_fd); return; }

    c->client_fd = client_fd;
    c->server_fd = -1;
    c->client_addr = *caddr;
    snprintf(c->dst_host, sizeof c->dst_host, "%s", rule->dst_host);
    c->dst_port = rule->dst_port;
    snprintf(c->name, sizeof c->name, "%s", rule->name[0] ? rule->name : "rule");
    c->timeout  = rule->timeout;
    c->rule_idx = lst->rule_idx;
    c->sec_held = 1;
    c->sh       = sh_acquire(sh);
    atomic_store(&c->active, 1);
    atomic_store(&c->last_io, (long)time(NULL));
    atomic_store(&c->refcount, 1);

    /* Counters first: every failure path below unwinds via conn_release() */
    atomic_fetch_add(&sh->live_conns, 1);
    mon_conn(&sh->mon, c->rule_idx, 1);

    if (tb_init(&c->up_bucket,   rule->rate_value, rule->rate_unit) < 0 ||
        tb_init(&c->down_bucket, rule->rate_value, rule->rate_unit) < 0) {
        LOG(LOG_ERR, "[%s] rate limiter init failed", c->name);
        conn_release(c);
        return;
    }

    int on = 1;
    setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);

    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, FWD_THREAD_STACK);
    int rc = pthread_create(&t, &attr, tcp_conn_thread, c);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        LOG(LOG_ERR, "pthread_create: %s", strerror(rc));
        conn_release(c);
        return;
    }

    char ipbuf[INET6_ADDRSTRLEN];
    LOG(LOG_DEBUG, "[%s] TCP conn %s → %s:%d",
        c->name, sa_str(caddr, ipbuf, sizeof ipbuf),
        c->dst_host, c->dst_port);
}

static void *tcp_listener_thread(void *arg)
{
    listener_t *lst = (listener_t *)arg;

    while (atomic_load(&lst->running)) {
        struct sockaddr_storage caddr;
        socklen_t addrlen = sizeof caddr;

        int client_fd = accept4(lst->listen_fd, (struct sockaddr *)&caddr,
                                &addrlen, SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == ECONNABORTED)
                continue;
            if (errno == EINVAL)          /* listener was shut down */
                break;
            if (!atomic_load(&lst->running))
                break;
            if (errno == EMFILE || errno == ENFILE ||
                errno == ENOBUFS || errno == ENOMEM) {
                LOG(LOG_ERR, "accept: %s – backing off", strerror(errno));
                usleep(100 * 1000);
                continue;
            }
            LOG(LOG_ERR, "accept: %s", strerror(errno));
            break;
        }

        spawn_tcp_conn(lst, client_fd, &caddr);
    }
    return NULL;
}

/* ─────────────────────────────────────────────────────────────
 * UDP – bidirectional relay via per-client relay socket + epoll
 *
 * Sessions are heap nodes; the epoll data.ptr therefore stays valid
 * across table compaction (the old code stored array-slot addresses
 * and swapped slots on close, which could deliver replies to the
 * wrong client or touch freed relay sockets).
 * ───────────────────────────────────────────────────────────── */

typedef struct udp_session {
    struct sockaddr_storage client_addr;
    socklen_t               client_addrlen;
    int                     relay_fd;
    time_t                  last_activity;
    token_bucket_t          up_bucket;    /* client → dst */
    token_bucket_t          down_bucket;  /* dst → client */
    int                     rule_idx;
    proxy_shared_t         *sh;           /* borrowed – valid while the thread runs */
} udp_session_t;

static udp_session_t *find_udp_sess(udp_session_t **tbl, int n,
                                    const struct sockaddr_storage *addr)
{
    for (int i = 0; i < n; i++)
        if (sockaddr_equal(&tbl[i]->client_addr, addr)) return tbl[i];
    return NULL;
}

static void close_udp_sess(udp_session_t **tbl, int *n, int idx, int epfd)
{
    udp_session_t *s = tbl[idx];
    epoll_ctl(epfd, EPOLL_CTL_DEL, s->relay_fd, NULL);
    close(s->relay_fd);
    tb_destroy(&s->up_bucket);
    tb_destroy(&s->down_bucket);
    sec_release(&s->sh->sec, &s->client_addr);
    atomic_fetch_sub(&s->sh->live_conns, 1);
    free(s);
    tbl[idx] = tbl[--(*n)];   /* swap pointers – nodes themselves never move */
}

static udp_session_t *new_udp_sess(udp_session_t **tbl, int *n,
                                   const struct sockaddr_storage *caddr,
                                   socklen_t caddrlen,
                                   const rule_t *rule, int rule_idx,
                                   proxy_shared_t *sh, int epfd)
{
    if (*n >= MAX_UDP_SESSIONS) {
        LOG(LOG_WARN, "UDP session table full, dropping packet");
        return NULL;
    }
    if (atomic_load(&sh->live_conns) >= sh->global_max_conns) {
        LOG(LOG_WARN, "Global connection limit reached, dropping UDP packet");
        return NULL;
    }
    /* One sec slot per session (not per packet): the per-IP connection
     * limit now actually applies to UDP. */
    if (!sec_allow(&sh->sec, caddr, rule->max_connections)) {
        char ipbuf[INET6_ADDRSTRLEN];
        LOG(LOG_DEBUG, "UDP blocked from %s", sa_str(caddr, ipbuf, sizeof ipbuf));
        return NULL;
    }

    udp_session_t *s = calloc(1, sizeof *s);
    if (!s) { sec_release(&sh->sec, caddr); return NULL; }

    int relay = connect_with_timeout(rule->dst_host, rule->dst_port, PROTO_UDP, 0);
    if (relay < 0) { free(s); sec_release(&sh->sec, caddr); return NULL; }
    set_nonblocking(relay);

    s->client_addr    = *caddr;
    s->client_addrlen = caddrlen;
    s->relay_fd       = relay;
    s->last_activity  = time(NULL);
    s->rule_idx       = rule_idx;
    s->sh             = sh;

    if (tb_init(&s->up_bucket,   rule->rate_value, rule->rate_unit) < 0 ||
        tb_init(&s->down_bucket, rule->rate_value, rule->rate_unit) < 0) {
        tb_destroy(&s->up_bucket);
        tb_destroy(&s->down_bucket);
        close(relay); free(s);
        sec_release(&sh->sec, caddr);
        return NULL;
    }

    struct epoll_event ev;
    ev.events   = EPOLLIN;
    ev.data.ptr = s;    /* stable heap address */
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, relay, &ev) < 0) {
        LOG(LOG_ERR, "epoll_ctl(relay): %s", strerror(errno));
        tb_destroy(&s->up_bucket);
        tb_destroy(&s->down_bucket);
        close(relay); free(s);
        sec_release(&sh->sec, caddr);
        return NULL;
    }

    atomic_fetch_add(&sh->live_conns, 1);
    tbl[(*n)++] = s;
    return s;
}

static void *udp_listener_thread(void *arg)
{
    listener_t *lst = (listener_t *)arg;
    proxy_shared_t *sh = lst->sh;
    const rule_t *rule = lst->rule;

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) { LOG(LOG_ERR, "epoll_create: %s", strerror(errno)); return NULL; }

    struct epoll_event ev;
    ev.events   = EPOLLIN;
    ev.data.ptr = NULL;   /* NULL → this is the listen socket */
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, lst->listen_fd, &ev) < 0) {
        LOG(LOG_ERR, "epoll_ctl(listen): %s", strerror(errno));
        close(epfd);
        return NULL;
    }

    udp_session_t **sessions = calloc(MAX_UDP_SESSIONS, sizeof *sessions);
    char *buf = malloc(BUFFER_SIZE);
    if (!sessions || !buf) { free(sessions); free(buf); close(epfd); return NULL; }
    int sess_count = 0;

    struct epoll_event events[64];
    time_t last_sec_clean = time(NULL);

    while (atomic_load(&lst->running)) {
        int nev = epoll_wait(epfd, events, 64, 500);
        if (nev < 0) {
            if (errno == EINTR) continue;
            if (!atomic_load(&lst->running)) break;
            LOG(LOG_ERR, "epoll_wait: %s", strerror(errno));
            break;
        }
        time_t now = time(NULL);

        for (int i = 0; i < nev; i++) {
            if (events[i].data.ptr == NULL) {
                /* ── packet from a client ── */
                struct sockaddr_storage caddr;
                socklen_t caddrlen = sizeof caddr;
                ssize_t len = recvfrom(lst->listen_fd, buf, BUFFER_SIZE, 0,
                                       (struct sockaddr *)&caddr, &caddrlen);
                if (len <= 0) continue;

                udp_session_t *s = find_udp_sess(sessions, sess_count, &caddr);
                if (!s)
                    s = new_udp_sess(sessions, &sess_count, &caddr, caddrlen,
                                     rule, lst->rule_idx, sh, epfd);
                if (!s) continue;

                s->last_activity = now;

                if (!tb_consume(&s->up_bucket, (size_t)len)) {
                    mon_drop(&sh->mon, lst->rule_idx, (long)len, 1);
                    continue;
                }

                ssize_t w = send(s->relay_fd, buf, (size_t)len, MSG_NOSIGNAL);
                if (w < 0) {
                    /* not actually forwarded – count as dropped */
                    mon_drop(&sh->mon, lst->rule_idx, (long)len, 1);
                    if (errno == ECONNREFUSED)
                        LOG(LOG_DEBUG, "UDP destination refused (ICMP)");
                    continue;
                }
                mon_bytes(&sh->mon, lst->rule_idx, (long)len, 0);
                mon_pkts (&sh->mon, lst->rule_idx, 1, 0);

            } else {
                /* ── response from destination ── */
                udp_session_t *s = (udp_session_t *)events[i].data.ptr;
                ssize_t len = recv(s->relay_fd, buf, BUFFER_SIZE, 0);
                if (len < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                        continue;
                    /* queued ICMP error or fatal condition – retire the
                     * session so the level-triggered epoll cannot spin */
                    LOG(LOG_DEBUG, "UDP relay recv: %s", strerror(errno));
                    for (int j = 0; j < sess_count; j++)
                        if (sessions[j] == s) {
                            close_udp_sess(sessions, &sess_count, j, epfd);
                            break;
                        }
                    continue;
                }
                if (len == 0) continue;   /* not expected on UDP */

                s->last_activity = now;

                if (!tb_consume(&s->down_bucket, (size_t)len)) {
                    mon_drop(&sh->mon, lst->rule_idx, (long)len, 1);
                    continue;
                }

                ssize_t w = sendto(lst->listen_fd, buf, (size_t)len, MSG_NOSIGNAL,
                                   (struct sockaddr *)&s->client_addr,
                                   s->client_addrlen);
                if (w < 0) {
                    mon_drop(&sh->mon, lst->rule_idx, (long)len, 1);
                    continue;
                }
                mon_bytes(&sh->mon, lst->rule_idx, 0, (long)len);
                mon_pkts (&sh->mon, lst->rule_idx, 0, 1);
            }
        }

        /* ── cleanup idle sessions ── */
        for (int j = 0; j < sess_count; ) {
            if (now - sessions[j]->last_activity > UDP_SESSION_TTL) {
                LOG(LOG_DEBUG, "UDP session expired");
                close_udp_sess(sessions, &sess_count, j, epfd);
            } else {
                j++;
            }
        }

        /* ── periodic security cleanup (30 s) ── */
        if (now - last_sec_clean >= 30) {
            sec_cleanup(&sh->sec);
            last_sec_clean = now;
        }
    }

    /* teardown: close every session (the old indexed loop terminated
     * early because close_udp_sess swaps with the last element) */
    while (sess_count > 0)
        close_udp_sess(sessions, &sess_count, 0, epfd);

    free(buf);
    free(sessions);
    close(epfd);
    return NULL;
}

/* ─────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────── */

int proxy_init(proxy_ctx_t *ctx, config_t *cfg)
{
    if (!ctx || !cfg) return -1;
    memset(ctx, 0, sizeof *ctx);
    ctx->cfg = cfg;
    for (int i = 0; i < MAX_RULES; i++)
        ctx->listeners[i].listen_fd = -1;

    proxy_shared_t *sh = calloc(1, sizeof *sh);
    if (!sh) return -1;
    atomic_store(&sh->refcount, 1);
    atomic_store(&sh->stop, 0);
    atomic_store(&sh->live_conns, 0);
    sh->global_max_conns = cfg->global_max_conns > 0 ? cfg->global_max_conns
                                                     : MAX_CONNECTIONS;

    if (sec_init(&sh->sec, MAX_CONNS_PER_IP) < 0) {
        free(sh);
        return -1;
    }
    if (monitor_init(&sh->mon, cfg, cfg->monitor_interval) < 0) {
        sec_destroy(&sh->sec);
        free(sh);
        return -1;
    }
    ctx->sh = sh;

    for (int i = 0; i < cfg->rule_count; i++) {
        rule_t *r = &cfg->rules[i];

        if (ctx->count >= MAX_RULES) {
            LOG(LOG_WARN, "Listener table full (%d), ignoring remaining rules", MAX_RULES);
            break;
        }
        if (r->src_port <= 0 || r->src_port > 65535 ||
            r->dst_port <= 0 || r->dst_port > 65535 ||
            !r->dst_host[0] || !(r->rate_value > 0.0)) {
            LOG(LOG_ERR, "Rule '%s' has invalid parameters, skipping", r->name);
            continue;
        }

        int fd = make_listen_socket(r);
        if (fd < 0) continue;

        listener_t *lst = &ctx->listeners[ctx->count++];
        lst->rule      = r;
        lst->rule_idx  = i;
        lst->listen_fd = fd;
        lst->sh        = sh;
        atomic_store(&lst->running, 0);
        lst->started   = 0;

        LOG(LOG_INFO, "Listening on %s:%d → %s:%d [%s %.0f %s]",
            r->src_host[0] ? r->src_host : "*", r->src_port,
            r->dst_host, r->dst_port,
            r->protocol == PROTO_UDP ? "UDP" : "TCP",
            r->rate_value,
            r->rate_unit == RATE_PACKETS ? "pkt/s" : "kB/s");
    }

    if (ctx->count == 0) {
        LOG(LOG_ERR, "No listeners could be started");
        ctx->sh = NULL;
        sh_release(sh);
        return -1;
    }
    return 0;
}

void proxy_start(proxy_ctx_t *ctx)
{
    if (!ctx->sh) return;

    if (ctx->cfg->verbose && monitor_start(&ctx->sh->mon) < 0)
        LOG(LOG_WARN, "Could not start monitor thread");

    for (int i = 0; i < ctx->count; i++) {
        listener_t *lst = &ctx->listeners[i];
        atomic_store(&lst->running, 1);
        void *(*fn)(void *) = (lst->rule->protocol == PROTO_UDP)
                              ? udp_listener_thread
                              : tcp_listener_thread;
        if (pthread_create(&lst->thread, NULL, fn, lst) == 0)
            lst->started = 1;
        else {
            atomic_store(&lst->running, 0);
            LOG(LOG_ERR, "Cannot create listener thread for rule '%s': %s",
                lst->rule->name, strerror(errno));
        }
    }
}

void proxy_stop(proxy_ctx_t *ctx, int kill_conns)
{
    if (!ctx->sh) return;

    if (kill_conns)
        atomic_store(&ctx->sh->stop, 1);

    for (int i = 0; i < ctx->count; i++) {
        atomic_store(&ctx->listeners[i].running, 0);
        if (ctx->listeners[i].listen_fd >= 0)
            shutdown(ctx->listeners[i].listen_fd, SHUT_RDWR);
    }
    /* join only threads that were actually created */
    for (int i = 0; i < ctx->count; i++)
        if (ctx->listeners[i].started)
            pthread_join(ctx->listeners[i].thread, NULL);

    monitor_stop(&ctx->sh->mon);
}

int proxy_wait_drain(proxy_ctx_t *ctx, int timeout_secs)
{
    if (!ctx->sh) return 0;
    for (int i = 0; i < timeout_secs * 10; i++) {
        if (atomic_load(&ctx->sh->live_conns) <= 0) return 0;
        usleep(100 * 1000);
    }
    int left = atomic_load(&ctx->sh->live_conns);
    return left > 0 ? left : 0;
}

void proxy_destroy(proxy_ctx_t *ctx)
{
    for (int i = 0; i < ctx->count; i++) {
        if (ctx->listeners[i].listen_fd >= 0) {
            close(ctx->listeners[i].listen_fd);
            ctx->listeners[i].listen_fd = -1;
        }
    }
    ctx->count = 0;
    if (ctx->sh) {
        sh_release(ctx->sh);   /* freed when the last connection drains */
        ctx->sh = NULL;
    }
}
