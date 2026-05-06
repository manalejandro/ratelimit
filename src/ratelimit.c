#include "ratelimit.h"

int tb_init(token_bucket_t *tb, double rate, rate_unit_t unit)
{
    if (!tb || rate <= 0.0) return -1;

    memset(tb, 0, sizeof(*tb));
    tb->unit = unit;

    if (unit == RATE_KBYTES) {
        tb->refill_rate = rate * 1024.0;            /* bytes / sec  */
        tb->capacity    = rate * 1024.0 * TB_BURST_FACTOR;
    } else {
        tb->refill_rate = rate;                     /* packets / sec */
        tb->capacity    = rate * TB_BURST_FACTOR;
    }
    tb->tokens = tb->capacity;

    clock_gettime(CLOCK_MONOTONIC, &tb->last_update);
    return pthread_mutex_init(&tb->lock, NULL) == 0 ? 0 : -1;
}

void tb_destroy(token_bucket_t *tb)
{
    if (tb) pthread_mutex_destroy(&tb->lock);
}

/* Must be called with lock held. */
static void _refill(token_bucket_t *tb)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    double elapsed = (double)(now.tv_sec  - tb->last_update.tv_sec) +
                     (double)(now.tv_nsec - tb->last_update.tv_nsec) * 1e-9;

    tb->tokens += elapsed * tb->refill_rate;
    if (tb->tokens > tb->capacity) tb->tokens = tb->capacity;
    tb->last_update = now;
}

int tb_consume(token_bucket_t *tb, size_t data_size)
{
    double cost = (tb->unit == RATE_KBYTES) ? (double)data_size : 1.0;
    int allowed;

    pthread_mutex_lock(&tb->lock);
    _refill(tb);
    if (tb->tokens >= cost) {
        tb->tokens -= cost;
        allowed = 1;
    } else {
        allowed = 0;
    }
    pthread_mutex_unlock(&tb->lock);
    return allowed;
}

double tb_wait_ms(token_bucket_t *tb, size_t data_size)
{
    double cost = (tb->unit == RATE_KBYTES) ? (double)data_size : 1.0;
    double deficit;

    pthread_mutex_lock(&tb->lock);
    _refill(tb);
    deficit = cost - tb->tokens;
    pthread_mutex_unlock(&tb->lock);

    if (deficit <= 0.0) return 0.0;
    return (deficit / tb->refill_rate) * 1000.0;
}

void tb_reset(token_bucket_t *tb)
{
    pthread_mutex_lock(&tb->lock);
    tb->tokens = tb->capacity;
    clock_gettime(CLOCK_MONOTONIC, &tb->last_update);
    pthread_mutex_unlock(&tb->lock);
}
