#ifndef MONITOR_H
#define MONITOR_H

#include "common.h"
#include "config.h"

typedef struct {
    atomic_long active_conns;
    atomic_long total_conns;
    atomic_long bytes_in;
    atomic_long bytes_out;
    atomic_long pkts_in;
    atomic_long pkts_out;
    atomic_long dropped_bytes;
    atomic_long dropped_pkts;
} rule_stats_t;

typedef struct {
    rule_stats_t  stats[MAX_RULES];
    int           rule_count;
    config_t     *cfg;
    int           interval;       /* seconds */
    atomic_int    running;
    int           started;        /* 1 once the display thread exists */
    pthread_t     thread;
} monitor_ctx_t;

int  monitor_init (monitor_ctx_t *ctx, config_t *cfg, int interval);
int  monitor_start(monitor_ctx_t *ctx);   /* 0 on success, -1 on failure */
void monitor_stop (monitor_ctx_t *ctx);   /* no-op when not started      */

/* Called by proxy threads to record events */
void mon_conn  (monitor_ctx_t *ctx, int idx, int opened);   /* opened=1 → new, 0 → closed */
void mon_bytes (monitor_ctx_t *ctx, int idx, long bin, long bout);
void mon_pkts  (monitor_ctx_t *ctx, int idx, long pin, long pout);
void mon_drop  (monitor_ctx_t *ctx, int idx, long bytes, long pkts);

#endif /* MONITOR_H */
