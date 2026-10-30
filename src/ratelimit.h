#ifndef RATELIMIT_H
#define RATELIMIT_H

#include "common.h"

/* Token bucket – thread-safe, supports bytes/s and packets/s */

#define TB_BURST_FACTOR  4.0   /* max burst = rate * factor */

typedef struct {
    double          tokens;
    double          capacity;
    double          refill_rate;   /* tokens / second */
    rate_unit_t     unit;
    int             inited;        /* 1 after a successful tb_init */
    struct timespec last_update;
    pthread_mutex_t lock;
} token_bucket_t;

int    tb_init(token_bucket_t *tb, double rate, rate_unit_t unit);
void   tb_destroy(token_bucket_t *tb);

/* Returns 1 if allowed, 0 if limited. data_size is bytes (KBYTES mode)
 * or ignored (PACKETS mode – always costs 1 token).
 *
 * Chunks larger than the whole bucket are admitted only when the bucket
 * is completely full (and then drain it), so an oversized chunk can never
 * wedge the caller in an infinite wait. */
int    tb_consume(token_bucket_t *tb, size_t data_size);

/* How many milliseconds until `data_size` bytes / 1 packet would be allowed. */
double tb_wait_ms(token_bucket_t *tb, size_t data_size);

void   tb_reset(token_bucket_t *tb);

/* Bucket capacity (immutable after tb_init – safe without the lock). */
double tb_capacity(const token_bucket_t *tb);

/* Sensible maximum recv() chunk for a bucket, so a single chunk never
 * exceeds the bucket capacity by much. BUFFER_SIZE for packet mode. */
size_t tb_chunk_hint(const token_bucket_t *tb);

#endif /* RATELIMIT_H */
