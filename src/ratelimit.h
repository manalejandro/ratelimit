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
    struct timespec last_update;
    pthread_mutex_t lock;
} token_bucket_t;

int    tb_init(token_bucket_t *tb, double rate, rate_unit_t unit);
void   tb_destroy(token_bucket_t *tb);

/* Returns 1 if allowed, 0 if limited. data_size is bytes (KBYTES mode)
 * or ignored (PACKETS mode – always costs 1 token). */
int    tb_consume(token_bucket_t *tb, size_t data_size);

/* How many milliseconds until `data_size` bytes / 1 packet would be allowed. */
double tb_wait_ms(token_bucket_t *tb, size_t data_size);

void   tb_reset(token_bucket_t *tb);

#endif /* RATELIMIT_H */
