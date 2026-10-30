#ifndef PROXY_H
#define PROXY_H

#include "common.h"
#include "config.h"
#include "ratelimit.h"
#include "security.h"
#include "monitor.h"

/*
 * Heap-allocated, refcounted state shared between the proxy and every
 * in-flight connection.  It outlives proxy_destroy() until the last
 * connection drains, which makes SIGHUP reloads and shutdowns safe even
 * while detached forwarding threads are still running.
 */
typedef struct proxy_shared {
    atomic_int    refcount;        /* 1 (proxy) + 1 per live TCP conn */
    atomic_int    stop;            /* 1 → connections should exit promptly */
    atomic_int    live_conns;      /* TCP conns + UDP sessions        */
    int           global_max_conns;
    sec_ctx_t     sec;
    monitor_ctx_t mon;
} proxy_shared_t;

/* ── Per-connection state (TCP) ──────────────────────────── */
typedef struct tcp_conn {
    int                     client_fd;
    int                     server_fd;      /* -1 until the setup thread connects */
    struct sockaddr_storage client_addr;
    char                    dst_host[MAX_HOST_LEN];   /* copies – a conn must */
    int                     dst_port;                 /* never reference cfg  */
    char                    name[64];
    int                     timeout;        /* idle seconds, 0 = disabled */
    token_bucket_t          up_bucket;      /* client → server */
    token_bucket_t          down_bucket;    /* server → client */
    int                     rule_idx;
    proxy_shared_t         *sh;
    atomic_int              active;
    atomic_long             last_io;        /* time_t of last data, both dirs */
    atomic_int              refcount;       /* 1 per forwarding thread */
    int                     sec_held;       /* 1 while a sec slot is held */
} tcp_conn_t;

/* ── Per-listener state ──────────────────────────────────── */
typedef struct {
    rule_t         *rule;      /* valid while listeners run (joined first) */
    int             rule_idx;
    int             listen_fd;
    proxy_shared_t *sh;
    pthread_t       thread;
    atomic_int      running;
    int             started;   /* 1 once pthread_create succeeded */
} listener_t;

/* ── Top-level proxy context ─────────────────────────────── */
typedef struct {
    listener_t      listeners[MAX_RULES];
    int             count;
    proxy_shared_t *sh;
    config_t       *cfg;
} proxy_ctx_t;

int  proxy_init   (proxy_ctx_t *ctx, config_t *cfg);
void proxy_start  (proxy_ctx_t *ctx);
/* kill_conns: 1 → ask in-flight connections to finish (SIGTERM path);
 *             0 → let them drain naturally (SIGHUP reload path). */
void proxy_stop   (proxy_ctx_t *ctx, int kill_conns);
/* Wait up to timeout_secs for in-flight connections; returns how many remain. */
int  proxy_wait_drain(proxy_ctx_t *ctx, int timeout_secs);
void proxy_destroy(proxy_ctx_t *ctx);

#endif /* PROXY_H */
