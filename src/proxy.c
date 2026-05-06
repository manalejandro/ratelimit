#include "proxy.h"
#include <sys/epoll.h>

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
    const char *host = r->src_host[0] ? r->src_host : NULL;

    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc) { LOG(LOG_ERR, "getaddrinfo(%s:%d): %s", host ? host : "*", r->src_port, gai_strerror(rc)); return -1; }

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        int on = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);
        /* Keep-alive for TCP */
        if (r->protocol == PROTO_TCP)
            setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
        /* IPv6-only to avoid dual-stack ambiguity when host == "::" */
        if (rp->ai_family == AF_INET6)
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on);

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) { LOG(LOG_ERR, "bind(%s:%d): %s", host ? host : "*", r->src_port, strerror(errno)); return -1; }

    if (r->protocol == PROTO_TCP && listen(fd, SOMAXCONN) < 0) {
        LOG(LOG_ERR, "listen: %s", strerror(errno));
        close(fd); return -1;
    }
    return fd;
}

static int connect_to_dst(const rule_t *r)
{
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = (r->protocol == PROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;

    char port[8];
    snprintf(port, sizeof port, "%d", r->dst_port);

    int rc = getaddrinfo(r->dst_host, port, &hints, &res);
    if (rc) { LOG(LOG_ERR, "getaddrinfo(%s:%d): %s", r->dst_host, r->dst_port, gai_strerror(rc)); return -1; }

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* ─────────────────────────────────────────────────────────────
 * TCP – bidirectional forwarding
 * ───────────────────────────────────────────────────────────── */

typedef struct {
    tcp_conn_t     *conn;
    int             src_fd;
    int             dst_fd;
    token_bucket_t *bucket;
    int             upstream;   /* 1 = client→server, 0 = server→client */
} fwd_arg_t;

static void tcp_conn_release(tcp_conn_t *c)
{
    /* last thread to exit cleans up */
    if (atomic_fetch_sub(&c->refcount, 1) != 1) return;

    close(c->client_fd);
    close(c->server_fd);
    sec_release(c->sec, &c->client_addr);
    mon_conn(c->mon, c->rule_idx, 0);
    tb_destroy(&c->up_bucket);
    tb_destroy(&c->down_bucket);
    free(c);
}

static void *fwd_thread(void *arg)
{
    fwd_arg_t fa;
    memcpy(&fa, arg, sizeof fa);   /* copy before freeing */
    free(arg);

    char *buf = malloc(BUFFER_SIZE);
    if (!buf) { tcp_conn_release(fa.conn); return NULL; }

    struct timeval tv = { fa.conn->rule->timeout, 0 };
    setsockopt(fa.src_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    while (fa.conn->active) {
        ssize_t n = recv(fa.src_fd, buf, BUFFER_SIZE, 0);
        if (n <= 0) break;

        /* ── rate limiting with backpressure ── */
        while (!tb_consume(fa.bucket, (size_t)n)) {
            double ms = tb_wait_ms(fa.bucket, (size_t)n);
            if (ms < 1.0) ms = 1.0;
            struct timespec ts = {
                (time_t)(ms / 1000.0),
                (long)(fmod(ms, 1000.0) * 1e6)
            };
            nanosleep(&ts, NULL);
            if (!fa.conn->active) goto done;
        }

        /* ── full write ── */
        ssize_t sent = 0;
        while (sent < n) {
            ssize_t w = send(fa.dst_fd, buf + sent, (size_t)(n - sent), MSG_NOSIGNAL);
            if (w <= 0) goto done;
            sent += w;
        }

        if (fa.upstream) {
            mon_bytes(fa.conn->mon, fa.conn->rule_idx, (long)n, 0);
            mon_pkts (fa.conn->mon, fa.conn->rule_idx, 1,       0);
        } else {
            mon_bytes(fa.conn->mon, fa.conn->rule_idx, 0, (long)n);
            mon_pkts (fa.conn->mon, fa.conn->rule_idx, 0, 1);
        }
    }

done:
    free(buf);
    fa.conn->active = 0;
    /* Signal other direction to wake up and stop */
    shutdown(fa.src_fd, SHUT_RD);
    shutdown(fa.dst_fd, SHUT_WR);
    tcp_conn_release(fa.conn);
    return NULL;
}

static void spawn_tcp_conn(listener_t *lst, int client_fd,
                           const struct sockaddr_storage *caddr)
{
    /* connect to destination */
    int server_fd = connect_to_dst(lst->rule);
    if (server_fd < 0) {
        LOG(LOG_WARN, "Cannot connect to %s:%d", lst->rule->dst_host, lst->rule->dst_port);
        sec_release(lst->sec, caddr);
        close(client_fd);
        return;
    }

    tcp_conn_t *c = calloc(1, sizeof *c);
    if (!c) { close(client_fd); close(server_fd); return; }

    c->client_fd   = client_fd;
    c->server_fd   = server_fd;
    c->client_addr = *caddr;
    c->rule        = lst->rule;
    c->rule_idx    = lst->rule_idx;
    c->mon         = lst->mon;
    c->sec         = lst->sec;
    c->active      = 1;
    c->created_at  = time(NULL);
    atomic_store(&c->refcount, 2);

    if (tb_init(&c->up_bucket,   lst->rule->rate_value, lst->rule->rate_unit) < 0 ||
        tb_init(&c->down_bucket, lst->rule->rate_value, lst->rule->rate_unit) < 0) {
        free(c); close(client_fd); close(server_fd); return;
    }

    pthread_t t1, t2;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    fwd_arg_t *up   = malloc(sizeof *up);
    fwd_arg_t *down = malloc(sizeof *down);
    if (!up || !down) {
        free(up); free(down); free(c);
        close(client_fd); close(server_fd);
        pthread_attr_destroy(&attr);
        return;
    }

    up->conn = c; up->src_fd = client_fd; up->dst_fd = server_fd;
    up->bucket = &c->up_bucket;   up->upstream = 1;

    down->conn = c; down->src_fd = server_fd; down->dst_fd = client_fd;
    down->bucket = &c->down_bucket; down->upstream = 0;

    if (pthread_create(&t1, &attr, fwd_thread, up)   != 0) { free(up);   atomic_fetch_sub(&c->refcount,1); }
    if (pthread_create(&t2, &attr, fwd_thread, down) != 0) { free(down); atomic_fetch_sub(&c->refcount,1); }

    pthread_attr_destroy(&attr);
    mon_conn(lst->mon, lst->rule_idx, 1);

    char ipbuf[INET6_ADDRSTRLEN];
    LOG(LOG_DEBUG, "[%s] TCP conn %s → %s:%d",
        lst->rule->name, sa_str(caddr, ipbuf, sizeof ipbuf),
        lst->rule->dst_host, lst->rule->dst_port);
}

static void *tcp_listener_thread(void *arg)
{
    listener_t *lst = (listener_t *)arg;

    while (lst->running) {
        struct sockaddr_storage caddr;
        socklen_t addrlen = sizeof caddr;

        int client_fd = accept(lst->listen_fd, (struct sockaddr *)&caddr, &addrlen);
        if (client_fd < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            if (lst->running) LOG(LOG_ERR, "accept: %s", strerror(errno));
            break;
        }

        /* ── security checks ── */
        if (!sec_allow(lst->sec, &caddr)) {
            char ipbuf[INET6_ADDRSTRLEN];
            LOG(LOG_WARN, "Blocked connection from %s", sa_str(&caddr, ipbuf, sizeof ipbuf));
            close(client_fd);
            continue;
        }

        spawn_tcp_conn(lst, client_fd, &caddr);
    }
    return NULL;
}

/* ─────────────────────────────────────────────────────────────
 * UDP – bidirectional relay via per-client relay socket + epoll
 * ───────────────────────────────────────────────────────────── */

typedef struct {
    struct sockaddr_storage client_addr;
    socklen_t               client_addrlen;
    int                     relay_fd;
    time_t                  last_activity;
    token_bucket_t          bucket;
    int                     rule_idx;
    monitor_ctx_t          *mon;
} udp_session_t;

static udp_session_t *find_udp_sess(udp_session_t *tbl, int n,
                                     const struct sockaddr_storage *addr)
{
    for (int i = 0; i < n; i++)
        if (sockaddr_equal(&tbl[i].client_addr, addr)) return &tbl[i];
    return NULL;
}

static udp_session_t *new_udp_sess(udp_session_t *tbl, int *n,
                                    const struct sockaddr_storage *caddr,
                                    socklen_t caddrlen,
                                    const rule_t *rule, int rule_idx,
                                    monitor_ctx_t *mon, int epfd)
{
    if (*n >= MAX_UDP_SESSIONS) {
        LOG(LOG_WARN, "UDP session table full, dropping packet");
        return NULL;
    }

    /* socket connected to destination */
    int relay = connect_to_dst(rule);
    if (relay < 0) return NULL;
    set_nonblocking(relay);

    udp_session_t *s = &tbl[(*n)++];
    memset(s, 0, sizeof *s);
    s->client_addr    = *caddr;
    s->client_addrlen = caddrlen;
    s->relay_fd       = relay;
    s->last_activity  = time(NULL);
    s->rule_idx       = rule_idx;
    s->mon            = mon;
    tb_init(&s->bucket, rule->rate_value, rule->rate_unit);

    struct epoll_event ev;
    ev.events    = EPOLLIN;
    ev.data.ptr  = s;
    epoll_ctl(epfd, EPOLL_CTL_ADD, relay, &ev);

    return s;
}

static void close_udp_sess(udp_session_t *tbl, int *n, int idx, int epfd)
{
    udp_session_t *s = &tbl[idx];
    epoll_ctl(epfd, EPOLL_CTL_DEL, s->relay_fd, NULL);
    close(s->relay_fd);
    tb_destroy(&s->bucket);
    /* swap with last */
    tbl[idx] = tbl[--(*n)];
}

static void *udp_listener_thread(void *arg)
{
    listener_t *lst = (listener_t *)arg;

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) { LOG(LOG_ERR, "epoll_create: %s", strerror(errno)); return NULL; }

    struct epoll_event ev;
    ev.events   = EPOLLIN;
    ev.data.ptr = NULL;   /* NULL → this is the listen socket */
    epoll_ctl(epfd, EPOLL_CTL_ADD, lst->listen_fd, &ev);

    udp_session_t *sessions = calloc(MAX_UDP_SESSIONS, sizeof *sessions);
    if (!sessions) { close(epfd); return NULL; }
    int sess_count = 0;

    char *buf = malloc(BUFFER_SIZE);
    if (!buf) { free(sessions); close(epfd); return NULL; }

    struct epoll_event events[64];

    while (lst->running) {
        int nev = epoll_wait(epfd, events, 64, 2000);
        time_t now = time(NULL);

        for (int i = 0; i < nev; i++) {
            if (events[i].data.ptr == NULL) {
                /* ── packet from a client ── */
                struct sockaddr_storage caddr;
                socklen_t caddrlen = sizeof caddr;
                ssize_t len = recvfrom(lst->listen_fd, buf, BUFFER_SIZE, 0,
                                       (struct sockaddr *)&caddr, &caddrlen);
                if (len <= 0) continue;

                if (!sec_allow(lst->sec, &caddr)) {
                    char ipbuf[INET6_ADDRSTRLEN];
                    LOG(LOG_DEBUG, "UDP blocked from %s", sa_str(&caddr, ipbuf, sizeof ipbuf));
                    continue;
                }

                udp_session_t *s = find_udp_sess(sessions, sess_count, &caddr);
                if (!s)
                    s = new_udp_sess(sessions, &sess_count, &caddr, caddrlen,
                                     lst->rule, lst->rule_idx, lst->mon, epfd);
                if (!s) { sec_release(lst->sec, &caddr); continue; }

                s->last_activity = now;

                if (!tb_consume(&s->bucket, (size_t)len)) {
                    mon_drop(lst->mon, lst->rule_idx, (long)len, 1);
                    sec_release(lst->sec, &caddr);
                    continue;
                }

                send(s->relay_fd, buf, (size_t)len, 0);
                mon_bytes(lst->mon, lst->rule_idx, (long)len, 0);
                mon_pkts (lst->mon, lst->rule_idx, 1, 0);
                sec_release(lst->sec, &caddr);

            } else {
                /* ── response from destination ── */
                udp_session_t *s = (udp_session_t *)events[i].data.ptr;
                ssize_t len = recv(s->relay_fd, buf, BUFFER_SIZE, 0);
                if (len <= 0) continue;

                s->last_activity = now;

                if (!tb_consume(&s->bucket, (size_t)len)) {
                    mon_drop(lst->mon, lst->rule_idx, (long)len, 1);
                    continue;
                }

                sendto(lst->listen_fd, buf, (size_t)len, 0,
                       (struct sockaddr *)&s->client_addr, s->client_addrlen);
                mon_bytes(lst->mon, lst->rule_idx, 0, (long)len);
                mon_pkts (lst->mon, lst->rule_idx, 0, 1);
            }
        }

        /* ── cleanup idle sessions ── */
        for (int i = 0; i < sess_count; ) {
            if (now - sessions[i].last_activity > UDP_SESSION_TTL) {
                LOG(LOG_DEBUG, "UDP session expired");
                close_udp_sess(sessions, &sess_count, i, epfd);
            } else {
                i++;
            }
        }

        /* ── periodic security cleanup ── */
        sec_cleanup(lst->sec);
    }

    /* teardown */
    for (int i = 0; i < sess_count; i++) close_udp_sess(sessions, &sess_count, i, epfd);
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

    if (sec_init(&ctx->sec, cfg->global_max_conns / (cfg->rule_count ? cfg->rule_count : 1)) < 0)
        return -1;

    if (monitor_init(&ctx->mon, cfg, cfg->monitor_interval) < 0)
        return -1;

    for (int i = 0; i < cfg->rule_count; i++) {
        rule_t *r = &cfg->rules[i];

        if (r->src_port <= 0 || r->src_port > 65535 ||
            r->dst_port <= 0 || r->dst_port > 65535 ||
            !r->dst_host[0] || r->rate_value <= 0.0) {
            LOG(LOG_ERR, "Rule '%s' has invalid parameters, skipping", r->name);
            continue;
        }

        int fd = make_listen_socket(r);
        if (fd < 0) continue;

        listener_t *lst = &ctx->listeners[ctx->count++];
        lst->rule     = r;
        lst->rule_idx = i;
        lst->listen_fd = fd;
        lst->sec      = &ctx->sec;
        lst->mon      = &ctx->mon;
        lst->running  = 0;

        LOG(LOG_INFO, "Listening on %s:%d → %s:%d [%s %.0f %s]",
            r->src_host[0] ? r->src_host : "*", r->src_port,
            r->dst_host, r->dst_port,
            r->protocol == PROTO_UDP ? "UDP" : "TCP",
            r->rate_value,
            r->rate_unit == RATE_PACKETS ? "pkt/s" : "kB/s");
    }
    return ctx->count > 0 ? 0 : -1;
}

void proxy_start(proxy_ctx_t *ctx)
{
    if (ctx->cfg->verbose)
        monitor_start(&ctx->mon);

    for (int i = 0; i < ctx->count; i++) {
        listener_t *lst = &ctx->listeners[i];
        lst->running = 1;
        void *(*fn)(void *) = (lst->rule->protocol == PROTO_UDP)
                              ? udp_listener_thread
                              : tcp_listener_thread;
        pthread_create(&lst->thread, NULL, fn, lst);
    }
}

void proxy_stop(proxy_ctx_t *ctx)
{
    for (int i = 0; i < ctx->count; i++) {
        ctx->listeners[i].running = 0;
        shutdown(ctx->listeners[i].listen_fd, SHUT_RDWR);
        pthread_join(ctx->listeners[i].thread, NULL);
    }
    if (ctx->cfg->verbose)
        monitor_stop(&ctx->mon);
}

void proxy_destroy(proxy_ctx_t *ctx)
{
    for (int i = 0; i < ctx->count; i++)
        close(ctx->listeners[i].listen_fd);
    sec_destroy(&ctx->sec);
}
