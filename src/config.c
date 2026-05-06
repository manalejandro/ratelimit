#include "config.h"
#include <ctype.h>

/* ── helpers ─────────────────────────────────────────────── */

static void trim(char *s)
{
    /* leading */
    char *p = s;
    while (isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    /* trailing */
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
}

static void strip_comment(char *s)
{
    char *p = strchr(s, '#');
    if (p) { *p = '\0'; trim(s); }
}

static void rule_defaults(rule_t *r)
{
    memset(r, 0, sizeof(*r));
    r->max_connections = MAX_CONNS_PER_IP;
    r->timeout         = DEFAULT_TIMEOUT;
    r->protocol        = PROTO_TCP;
    r->rate_unit       = RATE_KBYTES;
    r->rate_value      = 1024.0;   /* 1 MB/s */
}

/* ── public API ──────────────────────────────────────────── */

int config_init(config_t *cfg)
{
    if (!cfg) return -1;
    memset(cfg, 0, sizeof(*cfg));
    cfg->monitor_interval = 1;
    cfg->global_max_conns = MAX_CONNECTIONS;
    cfg->log_level        = LOG_INFO;
    return 0;
}

int config_load(config_t *cfg, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { LOG(LOG_ERR, "Cannot open config '%s': %s", path, strerror(errno)); return -1; }

    char   line[512];
    char   section[64] = "";
    rule_t cur;
    int    in_rule = 0;

    rule_defaults(&cur);

    while (fgets(line, (int)sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        trim(line);
        if (line[0] == '#' || line[0] == ';' || line[0] == '\0') continue;

        /* ── section header ── */
        if (line[0] == '[') {
            /* flush previous rule */
            if (in_rule && cur.src_port > 0 && cur.dst_port > 0 && cur.dst_host[0]) {
                if (cfg->rule_count < MAX_RULES)
                    cfg->rules[cfg->rule_count++] = cur;
                else
                    LOG(LOG_WARN, "Max rules (%d) reached, ignoring '%s'", MAX_RULES, cur.name);
            }
            char *end = strchr(line + 1, ']');
            if (end) *end = '\0';
            /* Truncate long section names to fit the buffer */
            memcpy(section, line + 1, sizeof(section) - 1);
            section[sizeof(section) - 1] = '\0';
            rule_defaults(&cur);
            /* cur.name has the same declared size as section */
            memcpy(cur.name, section, sizeof(cur.name));
            in_rule = (strcmp(section, "global") != 0);
            continue;
        }

        /* ── key = value ── */
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char key[128], val[MAX_HOST_LEN];
        strncpy(key, line, sizeof(key) - 1); key[sizeof(key)-1] = '\0'; trim(key);
        strncpy(val, eq + 1, sizeof(val) - 1); val[sizeof(val)-1] = '\0'; trim(val); strip_comment(val);

        if (strcmp(section, "global") == 0) {
            if      (!strcmp(key, "verbose"))               cfg->verbose          = atoi(val);
            else if (!strcmp(key, "monitor_interval"))      cfg->monitor_interval = atoi(val);
            else if (!strcmp(key, "global_max_connections"))cfg->global_max_conns = atoi(val);
            else if (!strcmp(key, "log_level"))             cfg->log_level        = atoi(val);
        } else if (in_rule) {
            if      (!strcmp(key, "src_host"))    { snprintf(cur.src_host, MAX_HOST_LEN, "%s", val); }
            else if (!strcmp(key, "src_port"))    { cur.src_port = atoi(val); }
            else if (!strcmp(key, "dst_host"))    { snprintf(cur.dst_host, MAX_HOST_LEN, "%s", val); }
            else if (!strcmp(key, "dst_port"))    { cur.dst_port = atoi(val); }
            else if (!strcmp(key, "protocol"))    { cur.protocol  = (!strcmp(val,"udp")||!strcmp(val,"UDP")) ? PROTO_UDP : PROTO_TCP; }
            else if (!strcmp(key, "rate"))        { cur.rate_value = atof(val); }
            else if (!strcmp(key, "rate_unit"))   { cur.rate_unit  = (!strcmp(val,"packets")||!strcmp(val,"pkt")) ? RATE_PACKETS : RATE_KBYTES; }
            else if (!strcmp(key, "max_connections")) { cur.max_connections = atoi(val); }
            else if (!strcmp(key, "timeout"))     { cur.timeout = atoi(val); }
        }
    }

    /* flush last rule */
    if (in_rule && cur.src_port > 0 && cur.dst_port > 0 && cur.dst_host[0])
        if (cfg->rule_count < MAX_RULES)
            cfg->rules[cfg->rule_count++] = cur;

    fclose(f);
    LOG(LOG_INFO, "Loaded %d rule(s) from '%s'", cfg->rule_count, path);
    return 0;
}

int config_save(const config_t *cfg, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) { LOG(LOG_ERR, "Cannot write config '%s': %s", path, strerror(errno)); return -1; }

    fprintf(f, "# ratelimit configuration\n# Generated automatically\n\n");
    fprintf(f, "[global]\n");
    fprintf(f, "verbose              = %d\n", cfg->verbose);
    fprintf(f, "monitor_interval     = %d\n", cfg->monitor_interval);
    fprintf(f, "global_max_connections = %d\n", cfg->global_max_conns);
    fprintf(f, "log_level            = %d\n\n", cfg->log_level);

    for (int i = 0; i < cfg->rule_count; i++) {
        const rule_t *r = &cfg->rules[i];
        fprintf(f, "[%s]\n", r->name[0] ? r->name : "rule");
        fprintf(f, "src_host        = %s\n", r->src_host[0] ? r->src_host : "0.0.0.0");
        fprintf(f, "src_port        = %d\n", r->src_port);
        fprintf(f, "dst_host        = %s\n", r->dst_host);
        fprintf(f, "dst_port        = %d\n", r->dst_port);
        fprintf(f, "protocol        = %s\n", r->protocol == PROTO_UDP ? "udp" : "tcp");
        fprintf(f, "rate            = %.2f\n", r->rate_value);
        fprintf(f, "rate_unit       = %s\n", r->rate_unit == RATE_PACKETS ? "packets" : "kbytes");
        fprintf(f, "max_connections = %d\n", r->max_connections);
        fprintf(f, "timeout         = %d\n\n", r->timeout);
    }

    fclose(f);
    LOG(LOG_INFO, "Config saved to '%s'", path);
    return 0;
}

int config_add_rule(config_t *cfg, const rule_t *rule)
{
    if (cfg->rule_count >= MAX_RULES) return -1;
    cfg->rules[cfg->rule_count++] = *rule;
    return 0;
}

void config_print(const config_t *cfg)
{
    printf("Loaded %d rule(s):\n", cfg->rule_count);
    for (int i = 0; i < cfg->rule_count; i++) {
        const rule_t *r = &cfg->rules[i];
        printf("  [%s] %s:%d -> %s:%d  proto=%s  rate=%.2f %s  max_conn=%d  timeout=%ds\n",
               r->name[0] ? r->name : "?",
               r->src_host[0] ? r->src_host : "*", r->src_port,
               r->dst_host, r->dst_port,
               r->protocol == PROTO_UDP ? "udp" : "tcp",
               r->rate_value,
               r->rate_unit == RATE_PACKETS ? "pkt/s" : "kB/s",
               r->max_connections,
               r->timeout);
    }
}
