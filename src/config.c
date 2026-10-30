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
    char *q = strchr(s, ';');
    if (q) { *q = '\0'; trim(s); }
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

/* Bounded int parser: rejects junk like "80abc" or "-5". */
static int parse_int_range(const char *s, int lo, int hi, int *out)
{
    if (!s || !*s) return -1;
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < lo || v > hi) return -1;
    *out = (int)v;
    return 0;
}

static int parse_double_range(const char *s, double lo, double hi, double *out)
{
    if (!s || !*s) return -1;
    char *end;
    errno = 0;
    double v = strtod(s, &end);
    if (errno != 0 || end == s || *end != '\0') return -1;
    if (!(v >= lo) || v > hi) return -1;      /* !(v>=lo) also rejects NaN */
    *out = v;
    return 0;
}

/* Duplicate check: same protocol + src host + src port already present? */
static int find_dup(const config_t *cfg, const rule_t *r)
{
    for (int i = 0; i < cfg->rule_count; i++) {
        const rule_t *o = &cfg->rules[i];
        if (o->protocol == r->protocol &&
            o->src_port == r->src_port &&
            strcmp(o->src_host, r->src_host) == 0)
            return 1;
    }
    return 0;
}

/* ── public API ──────────────────────────────────────────── */

int parse_port_spec(const char *s, int *p1, int *p2)
{
    if (!s || !*s || !p1 || !p2) return -1;

    char buf[64];
    if (strlen(s) >= sizeof buf) return -1;
    strcpy(buf, s);

    char *dash = strchr(buf, '-');
    long a, b;
    char *end;

    errno = 0;
    if (dash) {
        *dash = '\0';
        a = strtol(buf, &end, 10);
        if (errno != 0 || end == buf || *end != '\0') return -1;
        const char *bs = dash + 1;
        errno = 0;
        b = strtol(bs, &end, 10);
        if (errno != 0 || end == bs || *end != '\0') return -1;
    } else {
        a = strtol(buf, &end, 10);
        if (errno != 0 || end == buf || *end != '\0') return -1;
        b = a;
    }

    if (a < 1 || a > 65535 || b < 1 || b > 65535 || b < a) return -1;
    if (b - a + 1 > MAX_PORT_RANGE) return -1;

    *p1 = (int)a;
    *p2 = (int)b;
    return 0;
}

int config_init(config_t *cfg)
{
    if (!cfg) return -1;
    memset(cfg, 0, sizeof(*cfg));
    cfg->monitor_interval = 1;
    cfg->global_max_conns = MAX_CONNECTIONS;
    cfg->log_level        = LOG_INFO;
    return 0;
}

int config_add_rule(config_t *cfg, const rule_t *rule)
{
    if (!cfg || !rule) return -1;
    if (cfg->rule_count >= MAX_RULES) return -1;
    cfg->rules[cfg->rule_count++] = *rule;
    return 0;
}

int config_add_rule_range(config_t *cfg, const rule_t *proto)
{
    if (!cfg || !proto) return -1;

    int p1 = proto->src_port, p2 = proto->src_port_end;
    int q1 = proto->dst_port, q2 = proto->dst_port_end;
    if (p2 < p1) p2 = p1;
    if (q2 < q1) q2 = q1;

    int span_s = p2 - p1 + 1;
    int span_d = q2 - q1 + 1;

    if (p1 < 1 || p1 > 65535 || q1 < 1 || q1 > 65535) {
        LOG(LOG_ERR, "Rule '%s': ports must be in 1..65535", proto->name);
        return -1;
    }
    if (span_s > MAX_PORT_RANGE || span_d > MAX_PORT_RANGE) {
        LOG(LOG_ERR, "Rule '%s': port range too wide (max %d ports)",
            proto->name, MAX_PORT_RANGE);
        return -1;
    }
    if (span_s > 1 && span_d > 1 && span_s != span_d) {
        LOG(LOG_ERR, "Rule '%s': mismatched port ranges (%d src vs %d dst)",
            proto->name, span_s, span_d);
        return -1;
    }

    int n = span_s > span_d ? span_s : span_d;
    int added = 0;

    for (int i = 0; i < n; i++) {
        if (cfg->rule_count >= MAX_RULES) {
            LOG(LOG_WARN, "Max rules (%d) reached, range truncated", MAX_RULES);
            break;
        }

        rule_t r = *proto;
        r.src_port = r.src_port_end = p1 + (span_s > 1 ? i : 0);
        r.dst_port = r.dst_port_end = q1 + (span_d > 1 ? i : 0);

        if (proto->name[0]) {
            if (n > 1)
                snprintf(r.name, sizeof r.name, "%.50s-%d", proto->name, r.src_port);
            else
                snprintf(r.name, sizeof r.name, "%s", proto->name);
        } else {
            if (n > 1)
                snprintf(r.name, sizeof r.name, "rule%d", r.src_port);
            else
                snprintf(r.name, sizeof r.name, "rule%d", cfg->rule_count + 1);
        }

        if (find_dup(cfg, &r)) {
            LOG(LOG_WARN, "Duplicate listener %s:%d/%s ignored",
                r.src_host[0] ? r.src_host : "*", r.src_port,
                r.protocol == PROTO_UDP ? "udp" : "tcp");
            continue;
        }

        cfg->rules[cfg->rule_count++] = r;
        added++;
    }
    return added;
}

int config_validate(const config_t *cfg)
{
    for (int i = 0; i < cfg->rule_count; i++) {
        const rule_t *r = &cfg->rules[i];
        if (!isfinite(r->rate_value) || r->rate_value <= 0.0) {
            LOG(LOG_ERR, "Rule '%s': rate must be > 0", r->name);
            return -1;
        }
        if (r->rate_value > 1e9) {
            LOG(LOG_ERR, "Rule '%s': rate absurdly large", r->name);
            return -1;
        }
        if (r->src_port < 1 || r->src_port > 65535 ||
            r->dst_port < 1 || r->dst_port > 65535 ||
            !r->dst_host[0]) {
            LOG(LOG_ERR, "Rule '%s': invalid address or port", r->name);
            return -1;
        }
        if (r->max_connections < 1 || r->timeout < 0) {
            LOG(LOG_ERR, "Rule '%s': invalid max_connections/timeout", r->name);
            return -1;
        }
    }
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
        line[strcspn(line, "\r\n")] = '\0';
        trim(line);
        if (line[0] == '#' || line[0] == ';' || line[0] == '\0') continue;

        /* ── section header ── */
        if (line[0] == '[') {
            /* flush previous rule (expands port ranges) */
            if (in_rule && cur.src_port > 0 && cur.dst_port > 0 && cur.dst_host[0]) {
                if (config_add_rule_range(cfg, &cur) <= 0)
                    LOG(LOG_WARN, "Section [%s]: invalid or empty, skipped", section);
            }

            char *end = strchr(line + 1, ']');
            if (!end) {
                LOG(LOG_WARN, "Malformed section header, ignoring line: %.40s", line);
                in_rule = 0;
                section[0] = '\0';
                continue;
            }
            *end = '\0';
            snprintf(section, sizeof section, "%.63s", line + 1);
            trim(section);
            if (!section[0]) {
                LOG(LOG_WARN, "Empty section name, ignoring");
                in_rule = 0;
                continue;
            }
            rule_defaults(&cur);
            in_rule = (strcasecmp(section, "global") != 0);
            continue;
        }

        /* ── key = value ── */
        char *eq = strchr(line, '=');
        if (!eq) {
            LOG(LOG_WARN, "Malformed line in [%s], ignoring: %.40s", section, line);
            continue;
        }
        *eq = '\0';
        char key[128], val[MAX_HOST_LEN];
        snprintf(key, sizeof key, "%.127s", line);    trim(key);
        snprintf(val, sizeof val, "%.255s", eq + 1);  trim(val); strip_comment(val);

        if (strcasecmp(section, "global") == 0) {
            int iv;
            if      (!strcmp(key, "verbose")) {
                if (parse_int_range(val, 0, 1, &iv) == 0) cfg->verbose = iv;
                else LOG(LOG_WARN, "[global] invalid verbose='%s'", val);
            }
            else if (!strcmp(key, "monitor_interval")) {
                if (parse_int_range(val, 1, 3600, &iv) == 0) cfg->monitor_interval = iv;
                else LOG(LOG_WARN, "[global] invalid monitor_interval='%s'", val);
            }
            else if (!strcmp(key, "global_max_connections")) {
                if (parse_int_range(val, 1, 10000000, &iv) == 0) cfg->global_max_conns = iv;
                else LOG(LOG_WARN, "[global] invalid global_max_connections='%s'", val);
            }
            else if (!strcmp(key, "log_level")) {
                if (parse_int_range(val, 0, 3, &iv) == 0) cfg->log_level = iv;
                else LOG(LOG_WARN, "[global] invalid log_level='%s'", val);
            }
            else LOG(LOG_WARN, "[global] unknown key '%s'", key);
        } else if (in_rule) {
            int p1, p2, iv; double dv;
            if      (!strcmp(key, "src_host"))    snprintf(cur.src_host, sizeof cur.src_host, "%s", val);
            else if (!strcmp(key, "src_port")) {
                if (parse_port_spec(val, &p1, &p2) == 0) { cur.src_port = p1; cur.src_port_end = p2; }
                else LOG(LOG_WARN, "[%s] invalid src_port='%s'", section, val);
            }
            else if (!strcmp(key, "dst_host"))    snprintf(cur.dst_host, sizeof cur.dst_host, "%s", val);
            else if (!strcmp(key, "dst_port")) {
                if (parse_port_spec(val, &p1, &p2) == 0) { cur.dst_port = p1; cur.dst_port_end = p2; }
                else LOG(LOG_WARN, "[%s] invalid dst_port='%s'", section, val);
            }
            else if (!strcmp(key, "protocol")) {
                if      (!strcasecmp(val, "udp")) cur.protocol = PROTO_UDP;
                else if (!strcasecmp(val, "tcp")) cur.protocol = PROTO_TCP;
                else LOG(LOG_WARN, "[%s] invalid protocol='%s' (using tcp)", section, val);
            }
            else if (!strcmp(key, "rate")) {
                if (parse_double_range(val, 1e-6, 1e9, &dv) == 0) cur.rate_value = dv;
                else LOG(LOG_WARN, "[%s] invalid rate='%s'", section, val);
            }
            else if (!strcmp(key, "rate_unit")) {
                if      (!strcasecmp(val, "packets") || !strcasecmp(val, "pkt")) cur.rate_unit = RATE_PACKETS;
                else if (!strcasecmp(val, "kbytes")  || !strcasecmp(val, "kb"))  cur.rate_unit = RATE_KBYTES;
                else LOG(LOG_WARN, "[%s] invalid rate_unit='%s' (using kbytes)", section, val);
            }
            else if (!strcmp(key, "max_connections")) {
                if (parse_int_range(val, 1, 1000000, &iv) == 0) cur.max_connections = iv;
                else LOG(LOG_WARN, "[%s] invalid max_connections='%s'", section, val);
            }
            else if (!strcmp(key, "timeout")) {
                if (parse_int_range(val, 0, 86400, &iv) == 0) cur.timeout = iv;
                else LOG(LOG_WARN, "[%s] invalid timeout='%s'", section, val);
            }
            else LOG(LOG_WARN, "[%s] unknown key '%s'", section, key);
        } else {
            LOG(LOG_WARN, "Key '%s' outside any section, ignoring", key);
        }
    }

    /* flush last rule */
    if (in_rule && cur.src_port > 0 && cur.dst_port > 0 && cur.dst_host[0]) {
        if (config_add_rule_range(cfg, &cur) <= 0)
            LOG(LOG_WARN, "Section [%s]: invalid or empty, skipped", section);
    }

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

    if (fclose(f) != 0) {
        LOG(LOG_ERR, "Error writing config '%s': %s", path, strerror(errno));
        return -1;
    }
    LOG(LOG_INFO, "Config saved to '%s'", path);
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
