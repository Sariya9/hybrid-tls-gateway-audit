/* Bounded HTTP/1.1 origin for the loopback application-admission study.
 * The parent supplies listeners, cancellation pipes and fresh credentials.
 * shortcut: 16 blocking workers, 3-second socket timeouts and a 60-second run
 * suit this fixture; revisit these bounds for a different workload.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#define HEADER_CAP 8192U
#define BODY_CAP 4096U
#define WORKERS 16
#define RUN_SECONDS 60U

struct request {
    char id[HEADER_CAP + 1];
    const char *path;
    size_t body_at, body_bytes;
    int close;
};

struct server {
    const char *name;
    SSL_CTX *ctx;
    char certificate[65];
    atomic_int stopping;
};

struct worker {
    struct server *server;
    pthread_t thread;
    uint64_t id;
    int fd, started, done, psk_offered;
};

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t worker_mutex = PTHREAD_MUTEX_INITIALIZER;

static void require(int ok, const char *why) {
    if (!ok) {
        fprintf(stderr, "origin error: %s (errno=%d)\n", why, errno);
        ERR_print_errors_fp(stderr);
        exit(22);
    }
}

static uint64_t monotonic_ns(void) {
    struct timespec now;
    require(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "monotonic clock");
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

/* All interpolated strings are fixed tokens, validated ASCII IDs or hex. */
static void event(const struct server *server, const char *name,
                  const char *fields, ...) {
    va_list args;
    require(pthread_mutex_lock(&log_mutex) == 0, "log lock");
    int ok = fprintf(stdout, "{\"monotonic_ns\":%" PRIu64
                     ",\"event\":\"%s\",\"origin\":\"%s\"",
                     monotonic_ns(), name, server->name) >= 0;
    va_start(args, fields);
    if (vfprintf(stdout, fields, args) < 0) ok = 0;
    va_end(args);
    if (fputs("}\n", stdout) == EOF || fflush(stdout) != 0) ok = 0;
    require(pthread_mutex_unlock(&log_mutex) == 0, "log unlock");
    require(ok, "event output");
}

static int ascii_alnum(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

static int token(unsigned char c) {
    return ascii_alnum(c) || (c != 0 && strchr("!#$%&'*+-.^_`|~", c) != NULL);
}

static int equal(const unsigned char *p, size_t n, const char *s) {
    if (n != strlen(s)) return 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = p[i];
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + ('a' - 'A'));
        if (c != (unsigned char)s[i]) return 0;
    }
    return 1;
}

static const unsigned char *crlf(const unsigned char *p,
                                 const unsigned char *end) {
    for (; p < end; ++p)
        if (*p == '\r' && end - p >= 2 && p[1] == '\n') return p;
    return NULL;
}

static int connection_tokens(const unsigned char *p, size_t n, int *close) {
    size_t i = 0;
    while (i < n) {
        while (i < n && (p[i] == ' ' || p[i] == '\t')) ++i;
        size_t begin = i;
        while (i < n && token(p[i])) ++i;
        if (i == begin) return 0;
        if (equal(p + begin, i - begin, "close")) *close = 1;
        while (i < n && (p[i] == ' ' || p[i] == '\t')) ++i;
        if (i == n) return 1;
        if (p[i++] != ',' || i == n) return 0;
    }
    return 0;
}

/* 1 = complete, 0 = incomplete, -1 = invalid. Binary bodies stay length-based.
 * consumed excludes any bytes belonging to the next persistent request. */
static int parse_request(const unsigned char *buf, size_t used,
                         struct request *request, size_t *consumed) {
    size_t header = 0;
    *consumed = 0;
    for (size_t i = 0; i + 3 < used && i + 3 < HEADER_CAP; ++i) {
        if (!memcmp(buf + i, "\r\n\r\n", 4)) {
            header = i + 4;
            break;
        }
    }
    if (!header) return used >= HEADER_CAP ? -1 : 0;
    const unsigned char *end = buf + header;
    const unsigned char *line = crlf(buf, end);
    if (!line) return -1;
    size_t n = (size_t)(line - buf);
    if (n == sizeof("POST /compat HTTP/1.1") - 1 &&
        !memcmp(buf, "POST /compat HTTP/1.1", n)) request->path = "/compat";
    else if (n == sizeof("POST /restricted HTTP/1.1") - 1 &&
             !memcmp(buf, "POST /restricted HTTP/1.1", n))
        request->path = "/restricted";
    else return -1;

    int have_length = 0, have_id = 0, have_host = 0;
    request->close = 0;
    request->body_bytes = 0;
    const unsigned char *p = line + 2;
    while (p < end - 2) {
        line = crlf(p, end);
        if (!line || line == p) return -1;
        const unsigned char *colon = memchr(p, ':', (size_t)(line - p));
        if (!colon || colon == p) return -1;
        for (const unsigned char *q = p; q < colon; ++q)
            if (!token(*q)) return -1;
        const unsigned char *value = colon + 1;
        for (const unsigned char *q = value; q < line; ++q)
            if ((*q < 0x20 && *q != '\t') || *q > 0x7e) return -1;
        const unsigned char *last = line;
        while (value < last && (*value == ' ' || *value == '\t')) ++value;
        while (last > value && (last[-1] == ' ' || last[-1] == '\t')) --last;
        size_t len = (size_t)(last - value), key = (size_t)(colon - p);
        if (equal(p, key, "content-length")) {
            if (have_length++ || !len) return -1;
            size_t length = 0;
            for (size_t i = 0; i < len; ++i) {
                if (value[i] < '0' || value[i] > '9') return -1;
                unsigned int digit = (unsigned int)(value[i] - '0');
                if (length > (BODY_CAP - digit) / 10) return -1;
                length = length * 10 + digit;
            }
            request->body_bytes = length;
        } else if (equal(p, key, "transfer-encoding") || equal(p, key, "expect")) {
            return -1;
        } else if (equal(p, key, "x-audit-id")) {
            if (have_id++ || !len || len >= sizeof(request->id)) return -1;
            for (size_t i = 0; i < len; ++i)
                if (!ascii_alnum(value[i]) && value[i] != '-' && value[i] != '_')
                    return -1;
            memcpy(request->id, value, len);
            request->id[len] = '\0';
        } else if (equal(p, key, "host")) {
            if (have_host++ || !len) return -1;
            for (size_t i = 0; i < len; ++i)
                if (value[i] <= 0x20 || value[i] == 0x7f) return -1;
        } else if (equal(p, key, "connection")) {
            if (!connection_tokens(value, len, &request->close)) return -1;
        }
        p = line + 2;
    }
    if (p != end - 2 || !have_length || !have_id || !have_host) return -1;
    if (used - header < request->body_bytes) return 0;
    request->body_at = header;
    *consumed = header + request->body_bytes;
    return 1;
}

static void hex(const unsigned char *bytes, size_t n, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        out[2 * i] = digits[bytes[i] >> 4];
        out[2 * i + 1] = digits[bytes[i] & 15];
    }
    out[2 * n] = '\0';
}

static int fingerprint(X509 *certificate, char out[65]) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int n = 0;
    if (!certificate || X509_digest(certificate, EVP_sha256(), digest, &n) != 1 ||
        n != 32) return 0;
    hex(digest, n, out);
    return 1;
}

static int no_psk(SSL *ssl, int *alert, void *arg) {
    (void)arg;
    struct worker *worker = SSL_get_app_data(ssl);
    const unsigned char *data;
    size_t n;
    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_psk, &data, &n))
        worker->psk_offered = 1;
    if (worker->psk_offered ||
        SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_early_data, &data, &n)) {
        *alert = SSL_AD_ILLEGAL_PARAMETER;
        return SSL_CLIENT_HELLO_ERROR;
    }
    return SSL_CLIENT_HELLO_SUCCESS;
}

static void tls_failure(struct worker *worker, SSL *ssl, const char *reason) {
    unsigned long error = ERR_peek_last_error();
    int no_shared_group = ERR_GET_LIB(error) == ERR_LIB_SSL &&
        (ERR_GET_REASON(error) == SSL_R_NO_SUITABLE_KEY_SHARE ||
         ERR_GET_REASON(error) == SSL_R_NO_SHARED_GROUPS);
    event(worker->server, "tls", ",\"connection_id\":%" PRIu64
          ",\"ok\":false,\"group\":null,\"version\":null,\"session_reused\":%s,"
          "\"certificate_sha256\":\"%s\",\"psk_offered\":%s,\"reason\":\"%s\","
          "\"no_shared_group\":%s,\"reason_code\":%d",
          worker->id, ssl && SSL_session_reused(ssl) ? "true" : "false",
          worker->server->certificate, worker->psk_offered ? "true" : "false", reason,
          no_shared_group ? "true" : "false", ERR_GET_REASON(error));
}

static int write_all(SSL *ssl, const void *data, size_t n) {
    const unsigned char *p = data;
    while (n) {
        size_t written = 0;
        ERR_clear_error();
        if (SSL_write_ex(ssl, p, n, &written) != 1 || written == 0 || written > n)
            return 0;
        p += written;
        n -= written;
    }
    return 1;
}

static void serve_requests(struct worker *worker, SSL *ssl) {
    unsigned char buf[HEADER_CAP + BODY_CAP];
    size_t used = 0;
    while (!atomic_load(&worker->server->stopping)) {
        struct request request;
        size_t consumed;
        int parsed = parse_request(buf, used, &request, &consumed);
        if (parsed < 0) break;
        if (!parsed) {
            size_t received = 0;
            ERR_clear_error();
            if (used == sizeof(buf) ||
                SSL_read_ex(ssl, buf + used, sizeof(buf) - used, &received) != 1 ||
                received == 0) break;
            used += received;
            continue;
        }
        if (atomic_load(&worker->server->stopping)) break;
        char body_hex[2 * BODY_CAP + 1];
        hex(buf + request.body_at, request.body_bytes, body_hex);
        event(worker->server, "application_accept", ",\"connection_id\":%" PRIu64
              ",\"request_id\":\"%s\",\"path\":\"%s\",\"body_hex\":\"%s\","
              "\"body_bytes\":%zu", worker->id, request.id, request.path,
              body_hex, request.body_bytes);
        char response[HEADER_CAP + 256];
        int n = snprintf(response, sizeof(response),
                         "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n"
                         "Content-Type: application/octet-stream\r\nX-Audit-ID: %s\r\n"
                         "X-Origin-Connection: %" PRIu64 "\r\nConnection: %s\r\n\r\n",
                         request.body_bytes, request.id, worker->id,
                         request.close ? "close" : "keep-alive");
        if (n < 0 || (size_t)n >= sizeof(response) ||
            !write_all(ssl, response, (size_t)n) ||
            !write_all(ssl, buf + request.body_at, request.body_bytes)) break;
        event(worker->server, "response", ",\"connection_id\":%" PRIu64
              ",\"request_id\":\"%s\",\"status\":200", worker->id, request.id);
        if (request.close) break;
        used -= consumed;
        memmove(buf, buf + consumed, used);
    }
}

static void *serve(void *arg) {
    struct worker *worker = arg;
    SSL *ssl = SSL_new(worker->server->ctx);
    int accepted = 0;
    if (!ssl || SSL_set_fd(ssl, worker->fd) != 1) {
        tls_failure(worker, ssl, "ssl_setup_failed");
    } else {
        SSL_set_app_data(ssl, worker);
        ERR_clear_error();
        if (SSL_accept(ssl) != 1) {
            tls_failure(worker, ssl, worker->psk_offered ? "psk_offered" : "handshake_failed");
        } else {
            const char *group = SSL_get0_group_name(ssl);
            char certificate[65];
            if (SSL_version(ssl) != TLS1_3_VERSION || SSL_session_reused(ssl) ||
                worker->psk_offered || !group ||
                (!equal((const unsigned char *)group, strlen(group), "x25519") &&
                 !equal((const unsigned char *)group, strlen(group), "x25519mlkem768")) ||
                !fingerprint(SSL_get_certificate(ssl), certificate)) {
                tls_failure(worker, ssl, "invalid_tls_state");
            } else {
                accepted = 1;
                event(worker->server, "tls", ",\"connection_id\":%" PRIu64
                      ",\"ok\":true,\"group\":\"%s\",\"version\":\"%s\","
                      "\"session_reused\":false,\"certificate_sha256\":\"%s\","
                      "\"psk_offered\":false", worker->id, group,
                      SSL_get_version(ssl), certificate);
                serve_requests(worker, ssl);
            }
        }
    }
    if (accepted && !atomic_load(&worker->server->stopping)) (void)SSL_shutdown(ssl);
    SSL_free(ssl);
    require(pthread_mutex_lock(&worker_mutex) == 0, "worker close lock");
    (void)close(worker->fd);
    worker->fd = -1;
    require(pthread_mutex_unlock(&worker_mutex) == 0, "worker close unlock");
    event(worker->server, "connection_closed", ",\"connection_id\":%" PRIu64, worker->id);
    require(pthread_mutex_lock(&worker_mutex) == 0, "worker done lock");
    worker->done = 1;
    require(pthread_mutex_unlock(&worker_mutex) == 0, "worker done unlock");
    return NULL;
}

static int descriptor(const char *s) {
    require(*s != '\0', "empty descriptor");
    unsigned int value = 0;
    for (; *s; ++s) {
        require(*s >= '0' && *s <= '9', "descriptor digits");
        unsigned int digit = (unsigned int)(*s - '0');
        require(value <= ((unsigned int)INT_MAX - digit) / 10, "descriptor overflow");
        value = value * 10 + digit;
    }
    require(value > STDERR_FILENO && fcntl((int)value, F_GETFD) >= 0,
            "inherited descriptor");
    return (int)value;
}

static int timed_socket(int fd) {
    int flags = fcntl(fd, F_GETFL);
    struct timeval timeout = {3, 0};
    return flags >= 0 && fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == 0 &&
           setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
           setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0;
}

static void hard_deadline(int sig) {
    (void)sig;
    static const char message[] = "origin hard deadline exceeded\n";
    (void)write(STDERR_FILENO, message, sizeof(message) - 1);
    _exit(124);
}

static int run(struct server *server, int listener, int cancel) {
    struct sockaddr_in address;
    socklen_t n = sizeof(address);
    int socket_type = 0;
    require(getsockname(listener, (struct sockaddr *)&address, &n) == 0 &&
            n == sizeof(address) && address.sin_family == AF_INET &&
            ntohl(address.sin_addr.s_addr) == 0x7f000001U && address.sin_port != 0,
            "listener must bind IPv4 127.0.0.1");
    /* SO_ACCEPTCONN returns ENOPROTOOPT on the study's macOS host. */
    n = sizeof(socket_type);
    require(getsockopt(listener, SOL_SOCKET, SO_TYPE, &socket_type, &n) == 0 &&
            socket_type == SOCK_STREAM, "inherited TCP socket");
    int flags = fcntl(listener, F_GETFL);
    require(flags >= 0 && fcntl(listener, F_SETFL, flags | O_NONBLOCK) == 0,
            "nonblocking listener");
    struct worker workers[WORKERS] = {{0}};
    uint64_t next_id = 0, until = monotonic_ns() + RUN_SECONDS * UINT64_C(1000000000);
    int status = 0;
    event(server, "listening", ",\"address\":\"127.0.0.1\",\"port\":%u",
          (unsigned int)ntohs(address.sin_port));
    for (;;) {
        int slot = -1;
        for (int i = 0; i < WORKERS; ++i) {
            require(pthread_mutex_lock(&worker_mutex) == 0, "worker reap lock");
            int done = workers[i].done;
            require(pthread_mutex_unlock(&worker_mutex) == 0, "worker reap unlock");
            if (workers[i].started && done) {
                require(pthread_join(workers[i].thread, NULL) == 0, "worker join");
                workers[i].started = 0;
            }
            if (!workers[i].started && slot < 0) slot = i;
        }
        if (monotonic_ns() >= until) {
            fputs("origin process deadline exceeded\n", stderr);
            status = 124;
            break;
        }
        struct pollfd fds[] = {{listener, slot < 0 ? 0 : POLLIN, 0}, {cancel, POLLIN, 0}};
        int ready = poll(fds, 2, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) { status = 22; break; }
        if (fds[1].revents & (POLLIN | POLLHUP)) break;
        if ((fds[0].revents | fds[1].revents) & (POLLERR | POLLNVAL | POLLHUP)) {
            status = 22;
            break;
        }
        if (slot < 0 || !(fds[0].revents & POLLIN)) continue;
        struct sockaddr_in peer;
        n = sizeof(peer);
        int fd = accept(listener, (struct sockaddr *)&peer, &n);
        if (fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ||
                errno == ECONNABORTED) continue;
            status = 22;
            break;
        }
        struct worker *worker = &workers[slot];
        memset(worker, 0, sizeof(*worker));
        worker->server = server;
        worker->fd = fd;
        worker->id = ++next_id;
        if (n != sizeof(peer) || peer.sin_family != AF_INET ||
            ntohl(peer.sin_addr.s_addr) != 0x7f000001U || !timed_socket(fd)) {
            tls_failure(worker, NULL, "socket_setup_failed");
            (void)close(fd);
            worker->fd = -1;
            event(server, "connection_closed", ",\"connection_id\":%" PRIu64, worker->id);
            status = 22;
            break;
        }
        int error = pthread_create(&worker->thread, NULL, serve, worker);
        if (error) {
            tls_failure(worker, NULL, "worker_creation_failed");
            (void)close(fd);
            worker->fd = -1;
            event(server, "connection_closed", ",\"connection_id\":%" PRIu64, worker->id);
            status = 22;
            break;
        }
        worker->started = 1;
    }
    atomic_store(&server->stopping, 1);
    (void)close(listener);
    (void)close(cancel);
    require(pthread_mutex_lock(&worker_mutex) == 0, "worker cancel lock");
    for (int i = 0; i < WORKERS; ++i)
        if (workers[i].started && workers[i].fd >= 0)
            (void)shutdown(workers[i].fd, SHUT_RDWR);
    require(pthread_mutex_unlock(&worker_mutex) == 0, "worker cancel unlock");
    for (int i = 0; i < WORKERS; ++i)
        if (workers[i].started)
            require(pthread_join(workers[i].thread, NULL) == 0, "cancelled worker join");
    event(server, "stopped", "");
    return status;
}

static int self_test(void) {
    struct request request;
    size_t consumed, checks = 0;
#define CHECK(condition) do { \
    ++checks; \
    if (!(condition)) { \
        fprintf(stderr, "self-test failed at line %d\n", __LINE__); \
        return 1; \
    } \
} while (0)
#define HEAD "POST /compat HTTP/1.1\r\nHost: origin.test\r\nX-Audit-ID: Aa09_-\r\n"
    static const struct { const char *text; int result; } cases[] = {
        {HEAD "Content-Length: 0\r\n\r\n", 1},
        {HEAD "content-length:\t0003 \t\r\n\r\na\nb", 1},
        {HEAD "Content-Length: 3\r\nConnection: Keep-Alive, CLOSE\r\n\r\nabc", 1},
        {"POST /restricted HTTP/1.1\r\nhost: origin.test\r\nx-audit-id: A-1_\r\n"
         "content-length: 1\r\n\r\nx", 1},
        {HEAD "Content-Length: 3\r\n\r\nab", 0},
        {HEAD "Content-Length: 4097\r\n\r\n", -1},
        {HEAD "Content-Length: 9999999999999999999999999\r\n\r\n", -1},
        {HEAD "Content-Length: -1\r\n\r\n", -1},
        {HEAD "Content-Length: +1\r\n\r\nx", -1},
        {HEAD "Content-Length: 1junk\r\n\r\nx", -1},
        {HEAD "Content-Length: 1 0\r\n\r\n", -1},
        {HEAD "Content-Length: 1,1\r\n\r\nx", -1},
        {HEAD "Content-Length: \r\n\r\n", -1},
        {HEAD "Content-Length: 0\r\ncOnTeNt-LeNgTh: 0\r\n\r\n", -1},
        {HEAD "Content-Length : 0\r\n\r\n", -1},
        {HEAD "Content-Length: 0\r\ntransfer-encoding: chunked\r\n\r\n", -1},
        {HEAD "Transfer-Encoding:\r\nContent-Length: 0\r\n\r\n", -1},
        {HEAD "Content-Length: 0\r\nExpect: 100-continue\r\n\r\n", -1},
        {HEAD "Content-Length: 0\r\nX-Audit-ID: duplicate\r\n\r\n", -1},
        {HEAD "Content-Length: 0\r\nHost: duplicate\r\n\r\n", -1},
        {HEAD "Content-Length: 0\r\n folded: value\r\n\r\n", -1},
        {HEAD "Content-Length: 0\r\nNo-colon\r\n\r\n", -1},
        {HEAD "Content-Length: 0\r\nBad(Name: x\r\n\r\n", -1},
        {HEAD "Content-Length: 0\r\nX-Test: bad\nvalue\r\n\r\n", -1},
        {HEAD "Content-Length: 0\r\nX-Test: bad\rvalue\r\n\r\n", -1},
        {HEAD "Content-Length: 0\r\nConnection: keep-alive,\r\n\r\n", -1},
        {HEAD "Content-Length: 0\r\nConnection: close bad\r\n\r\n", -1},
        {HEAD "\r\n", -1},
        {"POST /compat HTTP/1.1\r\nContent-Length: 0\r\nX-Audit-ID: x\r\n\r\n", -1},
        {"POST /compat HTTP/1.1\r\nHost: \r\nContent-Length: 0\r\nX-Audit-ID: x\r\n\r\n", -1},
        {"POST /compat HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", -1},
        {"GET /compat HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nX-Audit-ID: x\r\n\r\n", -1},
        {"POST /compat HTTP/1.0\r\nHost: x\r\nContent-Length: 0\r\nX-Audit-ID: x\r\n\r\n", -1},
        {"POST /other HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nX-Audit-ID: x\r\n\r\n", -1},
        {"POST /compat?x HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nX-Audit-ID: x\r\n\r\n", -1}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        CHECK(parse_request((const unsigned char *)cases[i].text, strlen(cases[i].text),
                            &request, &consumed) == cases[i].result);
    static const unsigned char binary[] = HEAD "Content-Length: 4\r\n\r\n\0\xff\r\n";
    CHECK(parse_request(binary, sizeof(binary) - 1, &request, &consumed) == 1);
    CHECK(request.body_bytes == 4 && consumed == sizeof(binary) - 1 &&
          !memcmp(binary + request.body_at, "\0\xff\r\n", 4));
    static const unsigned char valid[] = HEAD "Content-Length: 3\r\n\r\nabc";
    for (size_t i = 0; i < sizeof(valid) - 1; ++i)
        CHECK(parse_request(valid, i, &request, &consumed) == 0);
    unsigned char buf[HEADER_CAP + BODY_CAP + 64];
    memcpy(buf, valid, sizeof(valid) - 1);
    memcpy(buf + sizeof(valid) - 1, valid, sizeof(valid) - 1);
    CHECK(parse_request(buf, 2 * (sizeof(valid) - 1), &request, &consumed) == 1 &&
          consumed == sizeof(valid) - 1);
    size_t first = consumed;
    CHECK(parse_request(buf + first, first, &request, &consumed) == 1 && consumed == first);
    const char *prefix = HEAD "Content-Length: 4096\r\n\r\n";
    size_t n = strlen(prefix);
    memcpy(buf, prefix, n);
    memset(buf + n, 0xa5, BODY_CAP);
    CHECK(parse_request(buf, n + BODY_CAP, &request, &consumed) == 1 &&
          request.body_bytes == BODY_CAP && consumed == n + BODY_CAP);
    prefix = HEAD "Content-Length: 0\r\nX-Pad: ";
    n = strlen(prefix);
    memcpy(buf, prefix, n);
    memset(buf + n, 'a', HEADER_CAP + 1 - n);
    memcpy(buf + HEADER_CAP - 4, "\r\n\r\n", 4);
    CHECK(parse_request(buf, HEADER_CAP, &request, &consumed) == 1 && consumed == HEADER_CAP);
    memcpy(buf + HEADER_CAP - 4, "a\r\n\r\n", 5);
    CHECK(parse_request(buf, HEADER_CAP + 1, &request, &consumed) == -1);
    CHECK(parse_request(buf, HEADER_CAP, &request, &consumed) == -1);
    static const char id_prefix[] = "POST /compat HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nX-Audit-ID: ";
    n = sizeof(id_prefix) - 1;
    memcpy(buf, id_prefix, n);
    memcpy(buf + n + 1, "\r\n\r\n", 4);
    for (unsigned int c = 0; c <= 255; ++c) {
        buf[n] = (unsigned char)c;
        int expected = ascii_alnum((unsigned char)c) || c == '-' || c == '_' ? 1 : -1;
        CHECK(parse_request(buf, n + 5, &request, &consumed) == expected);
    }
    memcpy(buf, binary, sizeof(binary) - 1);
    buf[1] = 0;
    CHECK(parse_request(buf, sizeof(binary) - 1, &request, &consumed) == -1);
    CHECK(parse_request((const unsigned char *)cases[2].text, strlen(cases[2].text),
                        &request, &consumed) == 1 && request.close);
    char encoded[9];
    hex(binary + sizeof(binary) - 5, 4, encoded);
    CHECK(!strcmp(encoded, "00ff0d0a"));
    fprintf(stderr, "self-test: %zu checks passed\n", checks);
#undef HEAD
#undef CHECK
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        puts(OpenSSL_version(OPENSSL_VERSION));
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--self-test")) return self_test();
    if (argc != 7) {
        fputs("usage: origin_http NAME LISTEN_FD CANCEL_FD CERT KEY GROUPS\n", stderr);
        return 22;
    }
    require(!strcmp(argv[1], "legacy") || !strcmp(argv[1], "restricted"), "origin name");
    require(!strcmp(argv[6], "X25519") || !strcmp(argv[6], "X25519MLKEM768:X25519"),
            "declared group list");
    int listener = descriptor(argv[2]), cancel = descriptor(argv[3]);
    require(listener != cancel, "distinct inherited descriptors");
    require(signal(SIGPIPE, SIG_IGN) != SIG_ERR &&
            signal(SIGALRM, hard_deadline) != SIG_ERR, "signal handlers");
    /* Main normally cancels and joins at 60 seconds; also bound blocked logging. */
    alarm(RUN_SECONDS + 10);
    struct server server = {.name = argv[1], .ctx = SSL_CTX_new(TLS_server_method())};
    atomic_init(&server.stopping, 0);
    require(server.ctx != NULL, "SSL_CTX_new");
    require(SSL_CTX_set_min_proto_version(server.ctx, TLS1_3_VERSION) == 1 &&
            SSL_CTX_set_max_proto_version(server.ctx, TLS1_3_VERSION) == 1 &&
            SSL_CTX_set1_groups_list(server.ctx, argv[6]) == 1 &&
            SSL_CTX_set_num_tickets(server.ctx, 0) == 1 &&
            SSL_CTX_set_max_early_data(server.ctx, 0) == 1, "TLS configuration");
    SSL_CTX_set_session_cache_mode(server.ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(server.ctx, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_verify(server.ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_client_hello_cb(server.ctx, no_psk, NULL);
    require(SSL_CTX_use_certificate_chain_file(server.ctx, argv[4]) == 1 &&
            SSL_CTX_use_PrivateKey_file(server.ctx, argv[5], SSL_FILETYPE_PEM) == 1 &&
            SSL_CTX_check_private_key(server.ctx) == 1 &&
            fingerprint(SSL_CTX_get0_certificate(server.ctx), server.certificate),
            "origin credentials");
    int status = run(&server, listener, cancel);
    SSL_CTX_free(server.ctx);
    alarm(0);
    return status;
}
