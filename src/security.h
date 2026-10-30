#ifndef SECURITY_H
#define SECURITY_H

#include "common.h"

/*
 * Per-IP tracking table.  Provides:
 *   - connection-count limiting (per source IP, per-rule limit)
 *   - automatic / manual blacklisting
 *   - stale-entry eviction
 *
 * The table holds up to MAX_TRACKED_IPS entries in a flat array.
 * All IPv4 addresses are stored as IPv4-mapped IPv6 so the same
 * comparison logic works for both families.
 */

#define MAX_TRACKED_IPS     4096
#define BLACKLIST_TTL        300   /* seconds                            */
#define BLACKLIST_THRESHOLD    3   /* limit-rejections before blacklisting */
#define SEC_STALE_SECS       300   /* idle, conn-free entries are reapable */

typedef struct {
    struct in6_addr  addr;
    atomic_int       conn_count;
    atomic_long      total_conns;
    atomic_int       rejects;           /* consecutive limit rejections */
    time_t           first_seen;
    time_t           last_seen;
    time_t           blacklisted_until;
} ip_entry_t;

typedef struct {
    ip_entry_t      entries[MAX_TRACKED_IPS];
    int             count;
    pthread_rwlock_t lock;
    int             max_conns_per_ip;   /* default limit */
} sec_ctx_t;

int  sec_init   (sec_ctx_t *ctx, int default_max_conns);
void sec_destroy(sec_ctx_t *ctx);

/* Returns 1 → allowed (a slot was taken, must be matched by sec_release),
 *         0 → blocked/blacklisted (no slot taken).
 * max_conns <= 0 falls back to the context default. */
int  sec_allow  (sec_ctx_t *ctx, const struct sockaddr_storage *ss, int max_conns);
void sec_release(sec_ctx_t *ctx, const struct sockaddr_storage *ss);

void sec_blacklist(sec_ctx_t *ctx, const struct sockaddr_storage *ss, int secs);
void sec_cleanup  (sec_ctx_t *ctx);   /* evict stale entries */

#endif /* SECURITY_H */
