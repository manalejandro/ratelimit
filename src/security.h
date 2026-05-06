#ifndef SECURITY_H
#define SECURITY_H

#include "common.h"

/*
 * Per-IP tracking table.  Provides:
 *   - connection-count limiting (per source IP)
 *   - automatic / manual blacklisting
 *   - stale-entry eviction
 *
 * The table holds up to MAX_TRACKED_IPS entries in a flat array.
 * All IPv4 addresses are stored as IPv4-mapped IPv6 so the same
 * comparison logic works for both families.
 */

#define MAX_TRACKED_IPS    4096
#define BLACKLIST_TTL       300   /* seconds */
#define BLACKLIST_THRESHOLD   3   /* auto-blacklist after N × max_conns */

typedef struct {
    struct in6_addr  addr;
    atomic_int       conn_count;
    atomic_long      total_conns;
    time_t           first_seen;
    time_t           last_seen;
    time_t           blacklisted_until;
} ip_entry_t;

typedef struct {
    ip_entry_t      entries[MAX_TRACKED_IPS];
    int             count;
    pthread_rwlock_t lock;
    int             max_conns_per_ip;
} sec_ctx_t;

int  sec_init   (sec_ctx_t *ctx, int max_conns_per_ip);
void sec_destroy(sec_ctx_t *ctx);

/* Returns 1 → allowed, 0 → blocked/blacklisted. */
int  sec_allow  (sec_ctx_t *ctx, const struct sockaddr_storage *ss);
void sec_release(sec_ctx_t *ctx, const struct sockaddr_storage *ss);

void sec_blacklist(sec_ctx_t *ctx, const struct sockaddr_storage *ss, int secs);
void sec_cleanup  (sec_ctx_t *ctx);   /* evict stale entries */

#endif /* SECURITY_H */
