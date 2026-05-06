#include "common.h"
#include "config.h"
#include "proxy.h"

/* ── Globals ─────────────────────────────────────────────── */
int                   g_log_level = LOG_INFO;
volatile sig_atomic_t g_running   = 1;
volatile sig_atomic_t g_reload    = 0;

#define VERSION "1.0.0"

/* ── Signal handler ──────────────────────────────────────── */
static void sig_handler(int sig)
{
    if      (sig == SIGTERM || sig == SIGINT)  g_running = 0;
    else if (sig == SIGHUP)                    g_reload  = 1;
}

/* ── Usage ───────────────────────────────────────────────── */
static void usage(const char *prog)
{
    printf(
        "Usage: %s [OPTIONS]\n\n"
        "Options:\n"
        "  -s, --src  HOST:PORT       Source address to listen on (repeatable)\n"
        "  -d, --dst  HOST:PORT       Destination to forward to    (repeatable, paired with --src)\n"
        "  -r, --rate VALUE           Rate limit value (default: 1024)\n"
        "  -u, --unit kbytes|packets  Rate unit (default: kbytes)\n"
        "  -p, --proto tcp|udp        Protocol (default: tcp)\n"
        "  -n, --name NAME            Rule name for the last --src/--dst pair\n"
        "  -c, --config FILE          Load configuration from file\n"
        "  -S, --save-config FILE     Save current config to file and exit\n"
        "  -v, --verbose              Show real-time connection monitor\n"
        "  -i, --interval SECS        Monitor refresh interval (default: 1)\n"
        "  -m, --max-conn N           Max connections per source IP (default: %d)\n"
        "  -t, --timeout  SECS        Connection idle timeout (default: %d)\n"
        "  -L, --log-level 0-3        Log level 0=ERR 1=WARN 2=INFO 3=DBG (default: 2)\n"
        "  -h, --help                 Show this help\n"
        "  -V, --version              Show version\n\n"
        "Examples:\n"
        "  # Single rule (TCP, 512 kB/s)\n"
        "  %s -s 0.0.0.0:8080 -d 127.0.0.1:80 -r 512 -u kbytes\n\n"
        "  # Multiple rules\n"
        "  %s -s 0.0.0.0:8080 -d 10.0.0.1:80 -r 1024 -u kbytes \\\n"
        "     -s [::]:8443   -d 10.0.0.1:443  -r 100  -u packets  -p tcp\n\n"
        "  # Load from config and show monitor\n"
        "  %s -c ratelimit.conf -v\n\n"
        "  # Save auto-generated config\n"
        "  %s -s 0.0.0.0:3000 -d 127.0.0.1:3001 -r 256 -S output.conf\n\n"
        "IPv6 syntax:  [::]:port  or  [2001:db8::1]:port\n",
        prog, MAX_CONNS_PER_IP, DEFAULT_TIMEOUT,
        prog, prog, prog, prog);
}

/* ── Parse HOST:PORT / [IPv6]:PORT ───────────────────────── */
static int parse_hostport(const char *str, char *host, size_t hlen, int *port)
{
    if (!str || !host || !port) return -1;

    if (str[0] == '[') {
        /* IPv6: [addr]:port */
        const char *end = strchr(str + 1, ']');
        if (!end || *(end + 1) != ':') return -1;
        size_t n = (size_t)(end - str - 1);
        if (n >= hlen) return -1;
        memcpy(host, str + 1, n);
        host[n] = '\0';
        *port = atoi(end + 2);
    } else {
        /* IPv4/hostname: addr:port */
        const char *colon = strrchr(str, ':');
        if (!colon) return -1;
        size_t n = (size_t)(colon - str);
        if (n >= hlen) return -1;
        memcpy(host, str, n);
        host[n] = '\0';
        *port = atoi(colon + 1);
    }

    if (*port <= 0 || *port > 65535) return -1;
    return 0;
}

/* ── Main ────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    static const struct option long_opts[] = {
        { "src",         required_argument, 0, 's' },
        { "dst",         required_argument, 0, 'd' },
        { "rate",        required_argument, 0, 'r' },
        { "unit",        required_argument, 0, 'u' },
        { "proto",       required_argument, 0, 'p' },
        { "name",        required_argument, 0, 'n' },
        { "config",      required_argument, 0, 'c' },
        { "save-config", required_argument, 0, 'S' },
        { "verbose",     no_argument,       0, 'v' },
        { "interval",    required_argument, 0, 'i' },
        { "max-conn",    required_argument, 0, 'm' },
        { "timeout",     required_argument, 0, 't' },
        { "log-level",   required_argument, 0, 'L' },
        { "help",        no_argument,       0, 'h' },
        { "version",     no_argument,       0, 'V' },
        { 0, 0, 0, 0 }
    };

    config_t cfg;
    config_init(&cfg);

    /* Accumulate CLI rules in a temporary buffer */
    rule_t  cli_rules[MAX_RULES];
    int     cli_count    = 0;
    rule_t *last_rule    = NULL;   /* last committed rule – for post-hoc flags */
    char    pending_src[MAX_HOST_LEN] = "";
    int     pending_src_port = 0;
    double  cur_rate     = 1024.0;
    rate_unit_t cur_unit = RATE_KBYTES;
    protocol_t  cur_proto = PROTO_TCP;
    char    cur_name[64] = "";
    int     cur_maxconn  = MAX_CONNS_PER_IP;
    int     cur_timeout  = DEFAULT_TIMEOUT;
    const char *save_path  = NULL;
    const char *config_path = NULL;

    int opt, optidx = 0;
    while ((opt = getopt_long(argc, argv, "s:d:r:u:p:n:c:S:vi:m:t:L:hV",
                              long_opts, &optidx)) != -1) {
        switch (opt) {
        case 's':
            if (parse_hostport(optarg, pending_src, sizeof pending_src,
                               &pending_src_port) < 0) {
                fprintf(stderr, "Invalid --src: '%s'\n", optarg);
                return 1;
            }
            last_rule = NULL;   /* new rule incoming – detach from previous */
            break;

        case 'd': {
            char dst_host[MAX_HOST_LEN]; int dst_port;
            if (parse_hostport(optarg, dst_host, sizeof dst_host, &dst_port) < 0) {
                fprintf(stderr, "Invalid --dst: '%s'\n", optarg);
                return 1;
            }
            if (!pending_src_port) {
                fprintf(stderr, "--dst requires a preceding --src\n");
                return 1;
            }
            if (cli_count >= MAX_RULES) {
                fprintf(stderr, "Too many rules (max %d)\n", MAX_RULES);
                return 1;
            }
            rule_t *ro = &cli_rules[cli_count++];
            memset(ro, 0, sizeof *ro);
            snprintf(ro->src_host, sizeof ro->src_host, "%s", pending_src);
            ro->src_port        = pending_src_port;
            snprintf(ro->dst_host, sizeof ro->dst_host, "%s", dst_host);
            ro->dst_port        = dst_port;
            ro->rate_value      = cur_rate;
            ro->rate_unit       = cur_unit;
            ro->protocol        = cur_proto;
            ro->max_connections = cur_maxconn;
            ro->timeout         = cur_timeout;
            if (cur_name[0])
                snprintf(ro->name, sizeof ro->name, "%s", cur_name);
            else
                snprintf(ro->name, sizeof ro->name, "rule%d", cli_count);
            last_rule = ro;

            /* reset per-rule state */
            pending_src_port = 0;
            pending_src[0]   = '\0';
            cur_name[0]      = '\0';
            break;
        }

        case 'r':
            cur_rate = atof(optarg);
            if (last_rule) last_rule->rate_value = cur_rate;
            break;
        case 'u':
            cur_unit = (!strcmp(optarg,"packets")||!strcmp(optarg,"pkt"))
                        ? RATE_PACKETS : RATE_KBYTES;
            if (last_rule) last_rule->rate_unit = cur_unit;
            break;
        case 'p':
            cur_proto = (!strcmp(optarg,"udp")||!strcmp(optarg,"UDP"))
                         ? PROTO_UDP : PROTO_TCP;
            if (last_rule) last_rule->protocol = cur_proto;
            break;
        case 'n':
            memcpy(cur_name, optarg, sizeof cur_name - 1);
            cur_name[sizeof cur_name - 1] = '\0';
            if (last_rule) snprintf(last_rule->name, sizeof last_rule->name, "%s", cur_name);
            break;
        case 'm':
            cur_maxconn = atoi(optarg);
            if (last_rule) last_rule->max_connections = cur_maxconn;
            break;
        case 't':
            cur_timeout = atoi(optarg);
            if (last_rule) last_rule->timeout = cur_timeout;
            break;
        case 'c': config_path  = optarg; break;
        case 'S': save_path    = optarg; break;
        case 'v': cfg.verbose  = 1;      break;
        case 'i': cfg.monitor_interval = atoi(optarg); break;
        case 'L': g_log_level  = atoi(optarg); cfg.log_level = g_log_level; break;
        case 'h': usage(argv[0]); return 0;
        case 'V': printf("ratelimit %s\n", VERSION); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    /* Load config file if given */
    if (config_path && config_load(&cfg, config_path) < 0)
        return 1;

    /* Merge CLI rules */
    for (int i = 0; i < cli_count; i++)
        config_add_rule(&cfg, &cli_rules[i]);

    if (cfg.rule_count == 0) {
        fprintf(stderr, "No rules defined. Use --src/--dst or --config.\n");
        usage(argv[0]);
        return 1;
    }

    /* Validate rate values */
    for (int i = 0; i < cfg.rule_count; i++) {
        rule_t *r = &cfg.rules[i];
        if (r->rate_value <= 0.0) {
            fprintf(stderr, "Rule '%s': rate must be > 0\n", r->name);
            return 1;
        }
    }

    /* Save config if requested */
    if (save_path) {
        config_save(&cfg, save_path);
        printf("Config saved to '%s'\n", save_path);
        return 0;
    }

    g_log_level = cfg.log_level;
    config_print(&cfg);

    /* Signal handling */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    signal(SIGPIPE, SIG_IGN);   /* ignore broken pipes */

    /* Init and start proxy */
    proxy_ctx_t proxy;
    if (proxy_init(&proxy, &cfg) < 0) {
        LOG(LOG_ERR, "Failed to initialise proxy");
        return 1;
    }
    proxy_start(&proxy);

    LOG(LOG_INFO, "ratelimit %s started. Send SIGINT/SIGTERM to stop, SIGHUP to reload.", VERSION);

    /* Main loop */
    while (g_running) {
        pause();
        if (g_reload) {
            g_reload = 0;
            if (config_path) {
                LOG(LOG_INFO, "SIGHUP: reloading config '%s'", config_path);
                /* Graceful reload: stop, reload, restart */
                proxy_stop(&proxy);
                proxy_destroy(&proxy);
                config_init(&cfg);
                if (config_load(&cfg, config_path) == 0) {
                    if (proxy_init(&proxy, &cfg) == 0)
                        proxy_start(&proxy);
                    else
                        LOG(LOG_ERR, "Reload failed – exiting");
                } else {
                    LOG(LOG_ERR, "Reload: cannot read config – keeping old state");
                }
            }
        }
    }

    LOG(LOG_INFO, "Shutting down...");
    proxy_stop(&proxy);
    proxy_destroy(&proxy);
    LOG(LOG_INFO, "Goodbye.");
    return 0;
}
