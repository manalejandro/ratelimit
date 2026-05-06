#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <getopt.h>

/* ── Limits ─────────────────────────────────────────────── */
#define MAX_HOST_LEN      256
#define MAX_RULES          64
#define MAX_CONNECTIONS  8192
#define MAX_CONNS_PER_IP  200
#define MAX_UDP_SESSIONS  512
#define BUFFER_SIZE     65536
#define DEFAULT_TIMEOUT    60   /* seconds */
#define UDP_SESSION_TTL   120   /* seconds of idle before cleanup */

/* ── Logging ─────────────────────────────────────────────── */
#define LOG_ERR   0
#define LOG_WARN  1
#define LOG_INFO  2
#define LOG_DEBUG 3

extern int                    g_log_level;
extern volatile sig_atomic_t  g_running;
extern volatile sig_atomic_t  g_reload;

#define LOG(lvl, ...) \
    do { \
        if ((lvl) <= g_log_level) { \
            const char *_tag = (lvl) == LOG_ERR  ? "ERR " : \
                               (lvl) == LOG_WARN ? "WARN" : \
                               (lvl) == LOG_INFO ? "INFO" : "DBG "; \
            fprintf(stderr, "[%s] ", _tag); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, "\n"); \
        } \
    } while (0)

/* ── Enumerations ────────────────────────────────────────── */
typedef enum { PROTO_TCP = 0, PROTO_UDP = 1 } protocol_t;
typedef enum { RATE_KBYTES = 0, RATE_PACKETS = 1 } rate_unit_t;

/* ── Utility ─────────────────────────────────────────────── */
static inline void set_nonblocking(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static inline int sockaddr_equal(const struct sockaddr_storage *a,
                                 const struct sockaddr_storage *b) {
    if (a->ss_family != b->ss_family) return 0;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
        const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
        return a4->sin_addr.s_addr == b4->sin_addr.s_addr &&
               a4->sin_port        == b4->sin_port;
    }
    const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
    const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
    return memcmp(&a6->sin6_addr, &b6->sin6_addr, 16) == 0 &&
           a6->sin6_port == b6->sin6_port;
}

static inline const char *sa_str(const struct sockaddr_storage *ss,
                                  char *buf, size_t len) {
    if (ss->ss_family == AF_INET)
        inet_ntop(AF_INET,  &((struct sockaddr_in  *)ss)->sin_addr, buf, len);
    else
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ss)->sin6_addr, buf, len);
    return buf;
}

#endif /* COMMON_H */
