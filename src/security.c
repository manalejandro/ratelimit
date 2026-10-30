#include "security.h"
#include <string.h>
#include <time.h>

/* Map a sockaddr_storage to a normalised in6_addr (IPv4-mapped when needed). */
static void ss_to_in6(const struct sockaddr_storage *ss, struct in6_addr *out)
{
    memset(out, 0, sizeof(*out));
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)ss;
        /* ::ffff:0:0/96 (RFC 4291 IPv4-mapped) */
        out->s6_addr[10] = 0xff;
        out->s6_addr[11] = 0xff;
        memcpy(&out->s6_addr[12], &s4->sin_addr.s_addr, 4);
    } else {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ss;
        *out = s6->sin6_addr;
    }
}

/* Format an in6_addr (un-mapping IPv4) for log output. */
static const char *in6_str(const struct in6_addr *a, char *buf, size_t len)
{
    if (IN6_IS_ADDR_V4MAPPED(a))
        inet_ntop(AF_INET, &a->s6_addr[12], buf, (socklen_t)len);
    else
        inet_ntop(AF_INET6, a, buf, (socklen_t)len);
    return buf;
}

/* Must be called with at least a read-lock held. */
static ip_entry_t *find_entry(sec_ctx_t *ctx, const struct in6_addr *addr)
{
    for (int i = 0; i < ctx->count; i++)
        if (memcmp(&ctx->entries[i].addr, addr, sizeof(*addr)) == 0)
            return &ctx->entries[i];
    return NULL;
}

/* Evict a victim entry (writer lock must be held).
 * Prefer connection-free entries; fall back to the globally oldest. */
static ip_entry_t *evict_oldest(sec_ctx_t *ctx)
{
    int victim = -1;
    for (int i = 0; i < ctx->count; i++) {
        if (atomic_load(&ctx->entries[i].conn_count) != 0) continue;
        if (victim < 0 ||
            ctx->entries[i].last_seen < ctx->entries[victim].last_seen)
            victim = i;
    }
    if (victim < 0) {                       /* everything is busy */
        victim = 0;
        for (int i = 1; i < ctx->count; i++)
            if (ctx->entries[i].last_seen < ctx->entries[victim].last_seen)
                victim = i;
    }
    return &ctx->entries[victim];
}

/* Remove idle, connection-free entries (writer lock must be held). */
static void sweep_stale_locked(sec_ctx_t *ctx, time_t now)
{
    for (int i = 0; i < ctx->count; ) {
        ip_entry_t *e = &ctx->entries[i];
        if (atomic_load(&e->conn_count) == 0 &&
            e->blacklisted_until <= now &&
            (now - e->last_seen) > SEC_STALE_SECS) {
            ctx->entries[i] = ctx->entries[--ctx->count];   /* swap with last */
        } else {
            i++;
        }
    }
}

/* ── public ──────────────────────────────────────────────── */

int sec_init(sec_ctx_t *ctx, int default_max_conns)
{
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->max_conns_per_ip = default_max_conns > 0 ? default_max_conns
                                                  : MAX_CONNS_PER_IP;
    return pthread_rwlock_init(&ctx->lock, NULL) == 0 ? 0 : -1;
}

void sec_destroy(sec_ctx_t *ctx)
{
    if (ctx) pthread_rwlock_destroy(&ctx->lock);
}

int sec_allow(sec_ctx_t *ctx, const struct sockaddr_storage *ss, int max_conns)
{
    if (max_conns <= 0) max_conns = ctx->max_conns_per_ip;

    struct in6_addr addr;
    ss_to_in6(ss, &addr);
    time_t now = time(NULL);

    pthread_rwlock_wrlock(&ctx->lock);

    ip_entry_t *e = find_entry(ctx, &addr);
    if (!e) {
        /* allocate – sweep stale entries first, then evict if still full */
        if (ctx->count >= MAX_TRACKED_IPS) {
            sweep_stale_locked(ctx, now);
            if (ctx->count >= MAX_TRACKED_IPS)
                e = evict_oldest(ctx);
            else
                e = &ctx->entries[ctx->count++];
        } else {
            e = &ctx->entries[ctx->count++];
        }

        memset(e, 0, sizeof(*e));
        e->addr       = addr;
        e->first_seen = now;
    }
    e->last_seen = now;

    /* check blacklist */
    if (e->blacklisted_until > now) {
        pthread_rwlock_unlock(&ctx->lock);
        return 0;
    }

    int cur = atomic_load(&e->conn_count);

    if (cur >= max_conns) {
        /*
         * Count rejections; a client that keeps hammering the limit is
         * blacklisted for BLACKLIST_TTL seconds.  (The old code compared
         * conn_count against max*THRESHOLD, which was unreachable because
         * conn_count is capped at max.)
         */
        int rj = atomic_fetch_add(&e->rejects, 1) + 1;
        if (rj >= BLACKLIST_THRESHOLD) {
            e->blacklisted_until = now + BLACKLIST_TTL;
            atomic_store(&e->rejects, 0);
            char ipbuf[INET6_ADDRSTRLEN];
            LOG(LOG_WARN, "Auto-blacklisted abusive IP %s for %d s (%d rejected connections)",
                in6_str(&addr, ipbuf, sizeof ipbuf), BLACKLIST_TTL, rj);
        }
        pthread_rwlock_unlock(&ctx->lock);
        return 0;
    }

    if (cur == 0)
        atomic_store(&e->rejects, 0);   /* decay: client behaved again */

    atomic_fetch_add(&e->conn_count, 1);
    atomic_fetch_add(&e->total_conns, 1);

    pthread_rwlock_unlock(&ctx->lock);
    return 1;
}

void sec_release(sec_ctx_t *ctx, const struct sockaddr_storage *ss)
{
    struct in6_addr addr;
    ss_to_in6(ss, &addr);

    pthread_rwlock_rdlock(&ctx->lock);
    ip_entry_t *e = find_entry(ctx, &addr);
    if (e) {
        int old = atomic_fetch_sub(&e->conn_count, 1);
        if (old <= 0) atomic_store(&e->conn_count, 0); /* clamp */
    }
    pthread_rwlock_unlock(&ctx->lock);
}

void sec_blacklist(sec_ctx_t *ctx, const struct sockaddr_storage *ss, int secs)
{
    struct in6_addr addr;
    ss_to_in6(ss, &addr);
    time_t until = time(NULL) + secs;

    pthread_rwlock_wrlock(&ctx->lock);
    ip_entry_t *e = find_entry(ctx, &addr);
    if (e) e->blacklisted_until = until;
    pthread_rwlock_unlock(&ctx->lock);
}

void sec_cleanup(sec_ctx_t *ctx)
{
    time_t now = time(NULL);
    pthread_rwlock_wrlock(&ctx->lock);
    sweep_stale_locked(ctx, now);
    pthread_rwlock_unlock(&ctx->lock);
}
