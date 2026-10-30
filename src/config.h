#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"
#include "ratelimit.h"

typedef struct {
    char        name[64];
    char        src_host[MAX_HOST_LEN];
    int         src_port;
    int         src_port_end;      /* inclusive; == src_port for a single port */
    char        dst_host[MAX_HOST_LEN];
    int         dst_port;
    int         dst_port_end;      /* inclusive; == dst_port for a single port */
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

/* Expand a rule with port ranges (src_port..src_port_end →
 * dst_port..dst_port_end) into concrete single-port rules.
 * Rules always keep src_port_end == src_port once stored.
 * Returns the number of rules added, or -1 on invalid ranges. */
int  config_add_rule_range(config_t *cfg, const rule_t *proto);

/* Remove rules duplicating an earlier listener (same protocol + src
 * host + src port), keeping the first.  Must run AFTER all CLI
 * post-hoc flags and config merging have settled, so that e.g. the
 * same port can legitimately exist once for TCP and once for UDP.
 * Returns the number of rules removed. */
int  config_dedup(config_t *cfg);

/* Validate every rule (rates, ports). 0 → ok, -1 → invalid (message logged). */
int  config_validate(const config_t *cfg);

/* Parse "N" or "A-B" (1..65535, A<=B, span <= MAX_PORT_RANGE). 0 → ok. */
int  parse_port_spec(const char *s, int *p1, int *p2);

void config_print(const config_t *cfg);

#endif /* CONFIG_H */
