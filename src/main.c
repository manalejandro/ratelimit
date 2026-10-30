#include "common.h"
#include "config.h"
#include "proxy.h"

/* ── Globals ─────────────────────────────────────────────── */
atomic_int g_log_level = LOG_INFO;

/* ── Usage ───────────────────────────────────────────────── */
static void usage(const char *prog)
{
    printf(
        "Usage: %s [OPTIONS]\n\n"
        "Options:\n"
        "  -s, --src  HOST:PORT[-PORT]  Source address to listen on (repeatable)\n"
        "  -d, --dst  HOST:PORT[-PORT]  Destination to forward to (paired with --src)\n"
        "  -r, --rate VALUE             Rate limit value (default: 1024)\n"
        "  -u, --unit kbytes|packets    Rate unit (default: kbytes)\n"
        "  -p, --proto tcp|udp          Protocol (default: tcp)\n"
        "  -n, --name NAME              Rule name for the next --src/--dst pair\n"
        "  -c, --config FILE            Load configuration from file\n"
        "  -S, --save-config FILE       Save current config to file and exit\n"
        "  -v, --verbose                Show real-time connection monitor\n"
        "  -i, --interval SECS          Monitor refresh interval (default: 1)\n"
        "  -m, --max-conn N             Max connections per source IP (default: %d)\n"
        "  -t, --timeout  SECS          Connection idle timeout (default: %d)\n"
        "  -L, --log-level 0-3          Log level 0=ERR 1=WARN 2=INFO 3=DBG (default: 2)\n"
        "  -h, --help                   Show this help\n"
        "  -V, --version                Show version\n\n"
        "Port ranges:\n"
        "  --src/--dst accept HOST:PORT-PORT.  Both ranges must span the same\n"
        "  number of ports (or the destination may be a single port, shared by\n"
        "  all source ports).  Each pair expands into one rule:\n"
        "    %s -s 0.0.0.0:8000-8009 -d 10.0.0.1:9000-9009 -r 512\n"
        "  maps 8000→9000, 8001→9001, … 8009→9009.\n\n"
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
        prog, prog, prog, prog, prog);
}

/* ── Strict option parsers ───────────────────────────────── */

static int opt_int(const char *arg, const char *what, int lo, int hi, int *out)
{
    char *end;
    errno = 0;
    long v = strtol(arg, &end, 10);
    if (errno != 0 || end == arg || *end != '\0' || v < lo || v > hi) {
        fprintf(stderr, "Invalid %s: '%s' (expected an integer in [%d, %d])\n",
                what, arg, lo, hi);
        return -1;
    }
    *out = (int)v;
    return 0;
}

static int opt_double(const char *arg, const char *what, double lo, double hi,
                      double *out)
{
    char *end;
    errno = 0;
    double v = strtod(arg, &end);
    if (errno != 0 || end == arg || *end != '\0' || !(v >= lo) || v > hi) {
        fprintf(stderr, "Invalid %s: '%s' (expected a number in [%g, %g])\n",
                what, arg, lo, hi);
        return -1;
    }
    *out = v;
    return 0;
}

/* ── Parse HOST:PORT / HOST:PORT-PORT / [IPv6]:PORT[-PORT] ─ */
static int parse_hostportrange(const char *str, char *host, size_t hlen,
                               int *p1, int *p2)
{
    if (!str || !host || !p1 || !p2) return -1;

    const char *portspec;
    if (str[0] == '[') {
        /* IPv6: [addr]:port[-port] */
        const char *end = strchr(str + 1, ']');
        if (!end || end[1] != ':') return -1;
        size_t n = (size_t)(end - str - 1);
        if (n == 0 || n >= hlen) return -1;
        memcpy(host, str + 1, n);
        host[n] = '\0';
        portspec = end + 2;
    } else {
        /* IPv4/hostname: addr:port[-port] */
        const char *colon = strrchr(str, ':');
        if (!colon) return -1;
        size_t n = (size_t)(colon - str);
        if (n >= hlen) return -1;
        memcpy(host, str, n);
        host[n] = '\0';
        portspec = colon + 1;
    }

    if (parse_port_spec(portspec, p1, p2) < 0) return -1;
    return 0;
}

/* ── Reload (SIGHUP) ─────────────────────────────────────── */
static int do_reload(proxy_ctx_t *proxy, config_t *cfg, const char *config_path)
{
    config_t *nc = calloc(1, sizeof *nc);
    if (!nc) return -1;
    config_init(nc);

    if (config_load(nc, config_path) != 0 || nc->rule_count == 0) {
        LOG(LOG_ERR, "Reload aborted: config invalid or empty – keeping current state");
        free(nc);
        return -1;
    }
    if (config_validate(nc) != 0) {
        LOG(LOG_ERR, "Reload aborted: config invalid – keeping current state");
        free(nc);
        return -1;
    }

    /* CLI overrides stay in effect across reloads */
    nc->verbose          = cfg->verbose;
    nc->monitor_interval = cfg->monitor_interval;
    nc->log_level        = cfg->log_level;

    /*
     * The new config is fully validated BEFORE the old proxy is torn
     * down.  Old connections keep draining against the refcounted
     * shared context; they never touch the new config.
     */
    proxy_stop(proxy, 0);
    proxy_destroy(proxy);

    memcpy(cfg, nc, sizeof *cfg);
    free(nc);
    g_log_level = cfg->log_level;
    config_print(cfg);

    if (proxy_init(proxy, cfg) != 0) {
        LOG(LOG_ERR, "Reload failed – exiting");
        exit(1);
    }
    proxy_start(proxy);
    LOG(LOG_INFO, "Reload complete: %d rule(s) active", cfg->rule_count);
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

    config_t *cfg = calloc(1, sizeof *cfg);
    if (!cfg) { fprintf(stderr, "Out of memory\n"); return 1; }
    config_init(cfg);

    /* Pending --src until its --dst completes the pair */
    char pending_src[MAX_HOST_LEN] = "";
    int  pending_p1 = 0, pending_p2 = 0, have_pending = 0;

    /* Per-rule defaults, sticky across pairs (as documented) */
    double      cur_rate    = 1024.0;
    rate_unit_t cur_unit    = RATE_KBYTES;
    protocol_t  cur_proto   = PROTO_TCP;
    char        cur_name[64] = "";
    int         cur_maxconn = MAX_CONNS_PER_IP;
    int         cur_timeout = DEFAULT_TIMEOUT;

    rule_t *last_rules   = NULL;     /* rules created by the last --dst  */
    int     last_rules_n = 0;        /* (1 for a single port, N for a range) */
    const char *save_path   = NULL;
    const char *config_path = NULL;
    int cli_verbose = -1, cli_interval = -1, cli_loglevel = -1;

    int opt, optidx = 0;
    while ((opt = getopt_long(argc, argv, "s:d:r:u:p:n:c:S:vi:m:t:L:hV",
                              long_opts, &optidx)) != -1) {
        switch (opt) {
        case 's':
            if (parse_hostportrange(optarg, pending_src, sizeof pending_src,
                                    &pending_p1, &pending_p2) < 0) {
                fprintf(stderr, "Invalid --src: '%s' (expected HOST:PORT[-PORT])\n", optarg);
                return 1;
            }
            have_pending = 1;
            last_rules = NULL; last_rules_n = 0;   /* new rule incoming */
            break;

        case 'd': {
            char dst_host[MAX_HOST_LEN];
            int q1, q2;
            if (parse_hostportrange(optarg, dst_host, sizeof dst_host,
                                    &q1, &q2) < 0) {
                fprintf(stderr, "Invalid --dst: '%s' (expected HOST:PORT[-PORT])\n", optarg);
                return 1;
            }
            if (!have_pending) {
                fprintf(stderr, "--dst requires a preceding --src\n");
                return 1;
            }

            rule_t proto;
            memset(&proto, 0, sizeof proto);
            snprintf(proto.src_host, sizeof proto.src_host, "%s", pending_src);
            proto.src_port     = pending_p1;
            proto.src_port_end = pending_p2;
            snprintf(proto.dst_host, sizeof proto.dst_host, "%s", dst_host);
            proto.dst_port     = q1;
            proto.dst_port_end = q2;
            proto.rate_value      = cur_rate;
            proto.rate_unit       = cur_unit;
            proto.protocol        = cur_proto;
            proto.max_connections = cur_maxconn;
            proto.timeout         = cur_timeout;
            snprintf(proto.name, sizeof proto.name, "%s", cur_name);

            int added = config_add_rule_range(cfg, &proto);
            if (added < 0) {
                fprintf(stderr, "Invalid rule for --dst '%s' (bad port ranges)\n", optarg);
                return 1;
            }
            if (added == 0) {
                fprintf(stderr, "Rule for --dst '%s' duplicates an existing listener\n", optarg);
                return 1;
            }
            /* Post-hoc flags (-r/-u/-p/-n/-m/-t after --dst) apply to every
             * rule the pair created, ranges included. */
            last_rules   = &cfg->rules[cfg->rule_count - added];
            last_rules_n = added;

            have_pending = 0;
            pending_src[0] = '\0';
            cur_name[0] = '\0';
            break;
        }

        case 'r':
            if (opt_double(optarg, "--rate", 1e-6, 1e9, &cur_rate) < 0) return 1;
            for (int k = 0; k < last_rules_n; k++)
                last_rules[k].rate_value = cur_rate;
            break;
        case 'u':
            if (!strcasecmp(optarg, "packets") || !strcasecmp(optarg, "pkt"))
                cur_unit = RATE_PACKETS;
            else if (!strcasecmp(optarg, "kbytes") || !strcasecmp(optarg, "kb"))
                cur_unit = RATE_KBYTES;
            else {
                fprintf(stderr, "Invalid --unit: '%s' (expected kbytes|packets)\n", optarg);
                return 1;
            }
            for (int k = 0; k < last_rules_n; k++)
                last_rules[k].rate_unit = cur_unit;
            break;
        case 'p':
            if (!strcasecmp(optarg, "udp"))
                cur_proto = PROTO_UDP;
            else if (!strcasecmp(optarg, "tcp"))
                cur_proto = PROTO_TCP;
            else {
                fprintf(stderr, "Invalid --proto: '%s' (expected tcp|udp)\n", optarg);
                return 1;
            }
            for (int k = 0; k < last_rules_n; k++)
                last_rules[k].protocol = cur_proto;
            break;
        case 'n':
            snprintf(cur_name, sizeof cur_name, "%s", optarg);
            for (int k = 0; k < last_rules_n; k++) {
                if (last_rules_n > 1)
                    snprintf(last_rules[k].name, sizeof last_rules[k].name,
                             "%.50s-%d", cur_name, last_rules[k].src_port);
                else
                    snprintf(last_rules[k].name, sizeof last_rules[k].name,
                             "%s", cur_name);
            }
            break;
        case 'm':
            if (opt_int(optarg, "--max-conn", 1, 1000000, &cur_maxconn) < 0) return 1;
            for (int k = 0; k < last_rules_n; k++)
                last_rules[k].max_connections = cur_maxconn;
            break;
        case 't':
            if (opt_int(optarg, "--timeout", 0, 86400, &cur_timeout) < 0) return 1;
            for (int k = 0; k < last_rules_n; k++)
                last_rules[k].timeout = cur_timeout;
            break;
        case 'c': config_path = optarg; break;
        case 'S': save_path   = optarg; break;
        case 'v': cli_verbose = 1; cfg->verbose = 1; break;
        case 'i':
            if (opt_int(optarg, "--interval", 1, 3600, &cli_interval) < 0) return 1;
            cfg->monitor_interval = cli_interval;
            break;
        case 'L':
            if (opt_int(optarg, "--log-level", 0, 3, &cli_loglevel) < 0) return 1;
            cfg->log_level = cli_loglevel;
            break;
        case 'h': usage(argv[0]); return 0;
        case 'V': printf("ratelimit %s\n", RATELIMIT_VERSION); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (have_pending) {
        fprintf(stderr, "--src '%s:%d' has no matching --dst\n",
                pending_src, pending_p1);
        return 1;
    }

    /* Load config file if given */
    if (config_path && config_load(cfg, config_path) < 0) {
        free(cfg);
        return 1;
    }

    /* CLI flags take precedence over the config file */
    if (cli_verbose  >= 0) cfg->verbose          = cli_verbose;
    if (cli_interval >= 0) cfg->monitor_interval = cli_interval;
    if (cli_loglevel >= 0) cfg->log_level        = cli_loglevel;

    if (cfg->rule_count == 0) {
        fprintf(stderr, "No rules defined. Use --src/--dst or --config.\n");
        usage(argv[0]);
        free(cfg);
        return 1;
    }
    if (config_validate(cfg) < 0) {
        free(cfg);
        return 1;
    }

    g_log_level = cfg->log_level;
    config_print(cfg);

    /* Save config if requested */
    if (save_path) {
        int rc = config_save(cfg, save_path);
        if (rc == 0) printf("Config saved to '%s'\n", save_path);
        free(cfg);
        return rc == 0 ? 0 : 1;
    }

    /*
     * Signals are handled synchronously with sigwait(): they are blocked
     * here (before any thread is created, so every thread inherits the
     * mask) and consumed one by one in the main loop.  This removes the
     * classic pause()/handler race that could hang shutdown forever.
     */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGHUP);
    if (pthread_sigmask(SIG_BLOCK, &mask, NULL) != 0) {
        fprintf(stderr, "pthread_sigmask: %s\n", strerror(errno));
        free(cfg);
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);   /* ignore broken pipes */

    /* Init and start proxy */
    proxy_ctx_t proxy;
    memset(&proxy, 0, sizeof proxy);
    if (proxy_init(&proxy, cfg) < 0) {
        LOG(LOG_ERR, "Failed to initialise proxy");
        free(cfg);
        return 1;
    }
    proxy_start(&proxy);

    LOG(LOG_INFO, "ratelimit %s started. Send SIGINT/SIGTERM to stop, SIGHUP to reload.",
        RATELIMIT_VERSION);

    /* Main loop */
    int running = 1;
    while (running) {
        int sig;
        int rc = sigwait(&mask, &sig);
        if (rc != 0) {
            if (rc == EINTR) continue;
            LOG(LOG_ERR, "sigwait: %s", strerror(rc));
            break;
        }
        if (sig == SIGTERM || sig == SIGINT) {
            running = 0;
        } else if (sig == SIGHUP) {
            if (!config_path) {
                LOG(LOG_WARN, "SIGHUP ignored: no --config file was given");
                continue;
            }
            LOG(LOG_INFO, "SIGHUP: reloading config '%s'", config_path);
            do_reload(&proxy, cfg, config_path);
        }
    }

    LOG(LOG_INFO, "Shutting down...");
    proxy_stop(&proxy, 1);
    int left = proxy_wait_drain(&proxy, DRAIN_TIMEOUT);
    if (left > 0)
        LOG(LOG_WARN, "%d connection(s) still draining, exiting anyway", left);
    proxy_destroy(&proxy);
    free(cfg);
    LOG(LOG_INFO, "Goodbye.");
    return 0;
}
