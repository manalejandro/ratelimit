#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"
#include "ratelimit.h"

typedef struct {
    char        name[64];
    char        src_host[MAX_HOST_LEN];
    int         src_port;
    char        dst_host[MAX_HOST_LEN];
    int         dst_port;
    protocol_t  protocol;
    rate_unit_t rate_unit;
    double      rate_value;        /* kbytes/s  or  packets/s */
    int         max_connections;   /* per source IP           */
    int         timeout;           /* seconds                 */
} rule_t;

typedef struct {
    rule_t  rules[MAX_RULES];
    int     rule_count;
    int     verbose;
    int     monitor_interval;      /* seconds between refreshes */
    int     global_max_conns;
    int     log_level;
} config_t;

int  config_init(config_t *cfg);
int  config_load(config_t *cfg, const char *path);
int  config_save(const config_t *cfg, const char *path);
int  config_add_rule(config_t *cfg, const rule_t *rule);
void config_print(const config_t *cfg);

#endif /* CONFIG_H */
