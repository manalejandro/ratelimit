#include "monitor.h"
#include <stdio.h>
#include <unistd.h>

/* ANSI helpers */
#define ANSI_CLR   "\033[2J\033[H"
#define ANSI_BOLD  "\033[1m"
#define ANSI_RESET "\033[0m"
#define ANSI_CYAN  "\033[36m"
#define ANSI_GREEN "\033[32m"
#define ANSI_RED   "\033[31m"

static void print_bar(void)
{
    printf("%-20s %8s %8s %12s %12s %10s %10s\n",
           "─────────────────", "────────", "────────",
           "────────────", "────────────", "──────────", "──────────");
}

static void *monitor_thread_fn(void *arg)
{
    monitor_ctx_t *ctx = (monitor_ctx_t *)arg;

    while (atomic_load(&ctx->running)) {
        printf(ANSI_CLR);
        printf(ANSI_BOLD ANSI_CYAN
               "  ratelimit – live monitor  (Ctrl-C to quit)\n" ANSI_RESET);
        printf("\n");
        printf(ANSI_BOLD
               "%-20s %8s %8s %12s %12s %10s %10s\n" ANSI_RESET,
               "Rule", "ActConn", "TotConn",
               "BytesIn", "BytesOut", "DroppedB", "DroppedP");
        print_bar();

        for (int i = 0; i < ctx->rule_count; i++) {
            rule_stats_t *s  = &ctx->stats[i];
            const rule_t *r  = &ctx->cfg->rules[i];
            long act  = (long)atomic_load(&s->active_conns);
            long tot  = (long)atomic_load(&s->total_conns);
            long bin  = (long)atomic_load(&s->bytes_in);
            long bout = (long)atomic_load(&s->bytes_out);
            long db   = (long)atomic_load(&s->dropped_bytes);
            long dp   = (long)atomic_load(&s->dropped_pkts);

            const char *color = (db > 0 || dp > 0) ? ANSI_RED : ANSI_GREEN;
            printf("%s%-20s%s %8ld %8ld %12ld %12ld %10ld %10ld\n",
                   color,
                   r->name[0] ? r->name : "rule",
                   ANSI_RESET,
                   act, tot, bin, bout, db, dp);
        }

        printf("\n  rate units: ");
        for (int i = 0; i < ctx->rule_count; i++) {
            const rule_t *r = &ctx->cfg->rules[i];
            printf("[%s: %.0f %s]  ",
                   r->name[0] ? r->name : "rule",
                   r->rate_value,
                   r->rate_unit == RATE_PACKETS ? "pkt/s" : "kB/s");
        }
        printf("\n");
        fflush(stdout);

        /* sleep in short slices so monitor_stop() is prompt */
        for (int i = 0; i < ctx->interval * 5 && atomic_load(&ctx->running); i++)
            usleep(200 * 1000);
    }
    return NULL;
}

/* ── public ──────────────────────────────────────────────── */

int monitor_init(monitor_ctx_t *ctx, config_t *cfg, int interval)
{
    if (!ctx || !cfg) return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->cfg        = cfg;
    ctx->rule_count = cfg->rule_count;
    if (ctx->rule_count > MAX_RULES) ctx->rule_count = MAX_RULES;
    ctx->interval   = interval > 0 ? interval : 1;
    atomic_store(&ctx->running, 0);
    return 0;
}

int monitor_start(monitor_ctx_t *ctx)
{
    if (ctx->started) return 0;
    atomic_store(&ctx->running, 1);
    if (pthread_create(&ctx->thread, NULL, monitor_thread_fn, ctx) != 0) {
        atomic_store(&ctx->running, 0);
        return -1;
    }
    ctx->started = 1;
    return 0;
}

void monitor_stop(monitor_ctx_t *ctx)
{
    if (!ctx->started) return;
    atomic_store(&ctx->running, 0);
    pthread_join(ctx->thread, NULL);
    ctx->started = 0;
}

void mon_conn(monitor_ctx_t *ctx, int idx, int opened)
{
    if (!ctx || idx < 0 || idx >= MAX_RULES) return;
    if (opened) {
        atomic_fetch_add(&ctx->stats[idx].total_conns,  1);
        atomic_fetch_add(&ctx->stats[idx].active_conns, 1);
    } else {
        /* never go below zero, even under concurrent updates */
        long v = atomic_load(&ctx->stats[idx].active_conns);
        while (v > 0 &&
               !atomic_compare_exchange_weak(&ctx->stats[idx].active_conns,
                                             &v, v - 1))
            ;
    }
}

void mon_bytes(monitor_ctx_t *ctx, int idx, long bin, long bout)
{
    if (!ctx || idx < 0 || idx >= MAX_RULES) return;
    if (bin)  atomic_fetch_add(&ctx->stats[idx].bytes_in,  bin);
    if (bout) atomic_fetch_add(&ctx->stats[idx].bytes_out, bout);
}

void mon_pkts(monitor_ctx_t *ctx, int idx, long pin, long pout)
{
    if (!ctx || idx < 0 || idx >= MAX_RULES) return;
    if (pin)  atomic_fetch_add(&ctx->stats[idx].pkts_in,  pin);
    if (pout) atomic_fetch_add(&ctx->stats[idx].pkts_out, pout);
}

void mon_drop(monitor_ctx_t *ctx, int idx, long bytes, long pkts)
{
    if (!ctx || idx < 0 || idx >= MAX_RULES) return;
    if (bytes) atomic_fetch_add(&ctx->stats[idx].dropped_bytes, bytes);
    if (pkts)  atomic_fetch_add(&ctx->stats[idx].dropped_pkts,  pkts);
}
