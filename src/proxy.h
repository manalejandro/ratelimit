#ifndef PROXY_H
#define PROXY_H

#include "common.h"
#include "config.h"
#include "ratelimit.h"
#include "security.h"
#include "monitor.h"

/* ── Per-connection state (TCP) ──────────────────────────── */
typedef struct {
    int                     client_fd;
    int                     server_fd;
    struct sockaddr_storage client_addr;
    token_bucket_t          up_bucket;    /* client → server */
    token_bucket_t          down_bucket;  /* server → client */
    rule_t                 *rule;
    int                     rule_idx;
    monitor_ctx_t          *mon;
    sec_ctx_t              *sec;
    volatile int            active;
    time_t                  created_at;
    atomic_int              refcount;     /* 2 = both fwd threads alive */
} tcp_conn_t;

/* ── Per-listener state ──────────────────────────────────── */
typedef struct {
    rule_t         *rule;
    int             rule_idx;
    int             listen_fd;
    sec_ctx_t      *sec;
    monitor_ctx_t  *mon;
    pthread_t       thread;
    volatile int    running;
} listener_t;

/* ── Top-level proxy context ─────────────────────────────── */
typedef struct {
    listener_t   listeners[MAX_RULES];
    int          count;
    sec_ctx_t    sec;
    monitor_ctx_t mon;
    config_t    *cfg;
} proxy_ctx_t;

int  proxy_init   (proxy_ctx_t *ctx, config_t *cfg);
void proxy_start  (proxy_ctx_t *ctx);
void proxy_stop   (proxy_ctx_t *ctx);
void proxy_destroy(proxy_ctx_t *ctx);

#endif /* PROXY_H */
