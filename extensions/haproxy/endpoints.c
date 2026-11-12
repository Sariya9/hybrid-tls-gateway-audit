/* Derived endpoint fixture for unmodified HAProxy. One exchange per process. Run through run_proxy_probe.py, not as a service.
 * shortcut: fixed 4096-byte frames and blocking I/O suit this bounded probe;
 * use a streaming event loop only if testing larger or concurrent exchanges.
 * Both server sockets are inherited from Python and checked for loopback.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define CAP 4096
static const unsigned char prefix[] = "origin-response\0";
/* Event observation times share CLOCK_MONOTONIC across these local processes.
 * They are not packet timestamps or an instrument of HAProxy's internal writes. */
static int trace_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    if (!strncmp(format, "{\"event\":", 9)) {
        struct timespec t;
        clock_gettime(CLOCK_MONOTONIC, &t);
        printf("{\"monotonic_ns\":%llu,", (unsigned long long)t.tv_sec * 1000000000ULL + t.tv_nsec);
        ++format;
    }
    int n = vprintf(format, args);
    va_end(args);
    return n;
}
#define printf trace_printf
/* Use printf for complete JSON records so every endpoint event is stamped. */

static void deadline(int sig) {
    (void)sig;
    static const char msg[] = "process deadline exceeded\n";
    (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
    _exit(124);
}

static void require(int ok, const char *why) {
    if (!ok) {
        fprintf(stderr, "probe error: %s (errno=%d)\n", why, errno);
        ERR_print_errors_fp(stderr);
        exit(22);
    }
}

static int number(const char *text, int max) {
    char *end;
    errno = 0;
    long value = strtol(text, &end, 10);
    require(!errno && end != text && !*end && value >= 0 && value <= max,
            "invalid descriptor or port");
    return (int)value;
}

static const char *leg(const SSL *s) { return SSL_get_app_data(s); }

static void alerts(const SSL *s, int where, int ret) {
    if (where & SSL_CB_ALERT)
        printf("{\"event\":\"alert\",\"leg\":\"%s\",\"direction\":\"%s\","
               "\"level\":%d,\"description\":%d}\n", leg(s),
               where & SSL_CB_READ ? "received" : "sent", ret >> 8, ret & 255);
}

static void messages(int writing, int version, int type, const void *buf,
                     size_t len, SSL *s, void *arg) {
    (void)version;
    (void)arg;
    if (type == SSL3_RT_HANDSHAKE && len)
        printf("{\"event\":\"handshake_message\",\"leg\":\"%s\","
               "\"direction\":\"%s\",\"type\":%u}\n", leg(s),
               writing ? "sent" : "received", ((const unsigned char *)buf)[0]);
    static const unsigned char hrr[32] = {
        0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
        0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
    if (type == SSL3_RT_HANDSHAKE && len >= 38 &&
        ((const unsigned char *)buf)[0] == SSL3_MT_SERVER_HELLO &&
        !memcmp((const unsigned char *)buf + 6, hrr, sizeof(hrr)))
        printf("{\"event\":\"hello_retry_request\",\"leg\":\"%s\",\"direction\":\"%s\"}\n",
               leg(s), writing ? "sent" : "received");
}

static int no_psk(SSL *s, int *alert, void *arg) {
    const unsigned char *data;
    size_t len;
    (void)arg;
    int present = SSL_client_hello_get0_ext(s, TLSEXT_TYPE_psk, &data, &len);
    printf("{\"event\":\"client_hello\",\"leg\":\"%s\",\"psk_offered\":%s}\n",
           leg(s), present ? "true" : "false");
    int sni = SSL_client_hello_get0_ext(s, TLSEXT_TYPE_server_name, &data, &len);
    printf("{\"event\":\"server_name_extension\",\"leg\":\"%s\",\"present\":%s}\n",
           leg(s), sni ? "true" : "false");
    if (present) {
        *alert = SSL_AD_ILLEGAL_PARAMETER;
        return SSL_CLIENT_HELLO_ERROR;
    }
    require(SSL_client_hello_get0_ext(s, TLSEXT_TYPE_supported_groups, &data, &len),
            "supported_groups extension missing");
    require(len >= 2 && ((size_t)data[0] * 256 + data[1]) == len - 2 &&
            (len - 2) % 2 == 0, "malformed supported_groups");
    printf("{\"event\":\"offered_groups\",\"leg\":\"%s\",\"iana_ids\":[", leg(s));
    for (size_t i = 2; i < len; i += 2)
        printf("%s%u", i == 2 ? "" : ",", (unsigned int)data[i] * 256 + data[i + 1]);
    puts("]}");
    require(SSL_client_hello_get0_ext(s, TLSEXT_TYPE_key_share, &data, &len),
            "key_share extension missing");
    require(len >= 2 && ((size_t)data[0] * 256 + data[1]) == len - 2,
            "malformed key_share vector");
    printf("{\"event\":\"offered_key_shares\",\"leg\":\"%s\",\"iana_ids\":[", leg(s));
    size_t i = 2, count = 0;
    while (i < len) {
        require(len - i >= 4, "short key share entry");
        unsigned int group = (unsigned int)data[i] * 256 + data[i + 1];
        size_t size = (size_t)data[i + 2] * 256 + data[i + 3];
        require(size <= len - i - 4, "key share length");
        printf("%s%u", count++ ? "," : "", group);
        i += 4 + size;
    }
    puts("]}");
    return SSL_CLIENT_HELLO_SUCCESS;
}

static void hex(const unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; ++i) printf("%02x", bytes[i]);
}

static void certificate(const char *kind, X509 *cert, SSL *s) {
    if (!cert) return;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len;
    require(X509_digest(cert, EVP_sha256(), hash, &len), "certificate digest");
    printf("{\"event\":\"certificate\",\"leg\":\"%s\",\"kind\":\"%s\","
           "\"sha256\":\"", leg(s), kind);
    hex(hash, len);
    puts("\"}");
}

static void tls_error(SSL *s, int error, int saved_errno, const char *stage) {
    unsigned long code = ERR_peek_last_error();
    const char *reason = ERR_reason_error_string(code);
    printf("{\"event\":\"tls_error\",\"leg\":\"%s\",\"stage\":\"%s\","
           "\"ssl_error\":%d,\"errno\":%d,\"reason_code\":%d,"
           "\"reason\":\"%s\",\"verify_code\":%ld,\"no_shared_group\":%s}\n",
           leg(s), stage, error, saved_errno, ERR_GET_REASON(code),
           reason ? reason : "none", SSL_get_verify_result(s),
           ERR_GET_LIB(code) == ERR_LIB_SSL &&
           (ERR_GET_REASON(code) == SSL_R_NO_SUITABLE_KEY_SHARE ||
            ERR_GET_REASON(code) == SSL_R_NO_SHARED_GROUPS) ? "true" : "false");
    ERR_print_errors_fp(stderr);
}

static int timed_socket(int fd) {
    require(fd >= 0, "socket");
    struct timeval timeout = {3, 0};
    require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
            "receive timeout");
    require(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0,
            "send timeout");
    return fd;
}

static int dial(int port) {
    require(port > 0, "zero destination port");
    int fd = timed_socket(socket(AF_INET, SOCK_STREAM, 0));
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port),
                              .sin_addr.s_addr = htonl(0x7f000001U)}; /* 127.0.0.1 */
    require(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0, "connect");
    return fd;
}

static int accept_one(int listener, int cancel) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    require(getsockname(listener, (struct sockaddr *)&addr, &len) == 0 &&
            addr.sin_family == AF_INET &&
            ntohl(addr.sin_addr.s_addr) == 0x7f000001U, "non-loopback listener");
    printf("{\"event\":\"listening\",\"address\":\"127.0.0.1\",\"port\":%u}\n",
           ntohs(addr.sin_port));
    struct pollfd fds[] = {{listener, POLLIN, 0}, {cancel, POLLIN, 0}};
    require(poll(fds, cancel < 0 ? 1 : 2, 5000) > 0, "accept timeout/poll failure");
    /* Prefer a queued connection over cancellation, so it cannot be hidden. */
    if (!(fds[0].revents & POLLIN)) {
        require(cancel >= 0 && (fds[1].revents & (POLLIN | POLLHUP)), "accept poll");
        printf("{\"event\":\"origin_cancelled_before_accept\"}\n");
        close(listener);
        close(cancel);
        return -1;
    }
    int fd = accept(listener, NULL, NULL);
    close(listener);
    if (cancel >= 0) close(cancel);
    printf("{\"event\":\"accepted\"}\n");
    return timed_socket(fd);
}

static SSL *peer(int fd, const char *which, const char *groups,
                 const char *cert, const char *key, const char *ca, const char *host) {
    int server = cert != NULL;
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    require(ctx != NULL, "SSL_CTX_new");
    require(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) &&
            SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) &&
            SSL_CTX_set1_groups_list(ctx, groups) &&
            SSL_CTX_set_num_tickets(ctx, 0) &&
            SSL_CTX_set_max_early_data(ctx, 0), "TLS configuration");
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_info_callback(ctx, alerts);
    SSL_CTX_set_msg_callback(ctx, messages);
    /* No PSK callbacks, cached sessions or SSL_set_session calls. */
    if (server) {
        SSL_CTX_set_client_hello_cb(ctx, no_psk, NULL);
        require(SSL_CTX_use_certificate_chain_file(ctx, cert) &&
                SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) &&
                SSL_CTX_check_private_key(ctx), "server credentials");
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        require(SSL_CTX_load_verify_locations(ctx, ca, NULL), "CA trust store");
    }
    SSL *s = SSL_new(ctx);
    SSL_CTX_free(ctx);
    require(s != NULL && SSL_set_fd(s, fd), "SSL_new/set_fd");
    SSL_set_app_data(s, (void *)which);
    if (server) SSL_set_accept_state(s);
    else {
        require(host && *host, "empty hostname");
        SSL_set_hostflags(s, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT |
                            X509_CHECK_FLAG_NO_WILDCARDS);
        const char *sni = !strcmp(which, "backend") ? "origin.test" : "proxy.test";
        require(SSL_set1_host(s, host) && SSL_set_tlsext_host_name(s, sni),
                "hostname verification/SNI");
        SSL_set_connect_state(s);
    }
    return s;
}

static int handshake(SSL *s) {
    ERR_clear_error();
    errno = 0;
    int rc = SSL_do_handshake(s), saved_errno = errno;
    int error = rc == 1 ? 0 : SSL_get_error(s, rc);
    if (rc != 1) tls_error(s, error, saved_errno, "handshake");
    const char *group = SSL_get0_group_name(s), *name = SSL_get0_peername(s);
    long verify = SSL_get_verify_result(s);
    printf("{\"event\":\"handshake\",\"leg\":\"%s\",\"ok\":%s,"
           "\"protocol\":\"%s\",\"group\":\"%s\",\"group_id\":%ld,"
           "\"session_reused\":%s,\"verify_code\":%ld,\"certificate_status\":\"%s\","
           "\"verified_hostname\":\"%s\"}\n", leg(s), rc == 1 ? "true" : "false",
           SSL_get_version(s), group ? group : "none", SSL_get_negotiated_group(s),
           SSL_session_reused(s) ? "true" : "false", verify,
           SSL_is_server(s) ? "client_auth_not_requested" :
           verify != X509_V_OK ? "rejected" : rc == 1 ? "verified" : "not_completed",
           name ? name : "none");
    certificate("local", SSL_get_certificate(s), s);
    certificate("peer", SSL_get0_peer_certificate(s), s);
    if (rc == 1) {
        require(SSL_version(s) == TLS1_3_VERSION && !SSL_session_reused(s) && group,
                "full TLS 1.3 with negotiated group required");
        if (!SSL_is_server(s))
            require(verify == X509_V_OK && name && SSL_get0_peer_certificate(s),
                    "verified server certificate and hostname required");
    }
    return rc == 1;
}

static void transfer(SSL *s, void *buf, size_t len, int writing,
                     const char *kind, const char *part) {
    unsigned char *p = buf;
    while (len) {
        /* Short writes exercise framing across multiple TLS records. */
        size_t done = 0, chunk = writing && len > 37 ? 37 : len;
        ERR_clear_error();
        errno = 0;
        int rc = writing ? SSL_write_ex(s, p, chunk, &done) : SSL_read_ex(s, p, chunk, &done);
        int saved_errno = errno;
        if (rc != 1) {
            int error = SSL_get_error(s, rc);
            tls_error(s, error, saved_errno, writing ? "write" : "read");
            exit(21);
        }
        require(done > 0 && done <= len, "TLS I/O progress");
        printf("{\"event\":\"%s_progress\",\"leg\":\"%s\","
               "\"kind\":\"%s\",\"part\":\"%s\",\"bytes\":%zu}\n",
               writing ? "write" : "read", leg(s), kind, part, done);
        p += done;
        len -= done;
    }
}

static size_t frame(SSL *s, unsigned char *buf, size_t len, int writing, const char *kind) {
    if (writing && strcmp(kind, "ready"))
        printf("{\"event\":\"payload_write_attempt\",\"leg\":\"%s\","
               "\"kind\":\"%s\",\"bytes\":%zu}\n", leg(s), kind, len);
    uint32_t size = htonl((uint32_t)len);
    transfer(s, &size, sizeof(size), writing, kind, "header");
    len = ntohl(size);
    require(len > 0 && len <= CAP, "frame length outside 1..4096");
    transfer(s, buf, len, writing, kind, "payload");
    printf("{\"event\":\"frame\",\"leg\":\"%s\",\"direction\":\"%s\","
           "\"kind\":\"%s\",\"bytes\":%zu,\"hex\":\"", leg(s),
           writing ? "sent" : "received", kind, len);
    hex(buf, len);
    puts("\"}");
    return len;
}

static void eof(SSL *s) {
    unsigned char extra;
    size_t done;
    ERR_clear_error();
    errno = 0;
    int rc = SSL_read_ex(s, &extra, 1, &done), saved_errno = errno;
    int error = SSL_get_error(s, rc);
    if (rc != 0 || error != SSL_ERROR_ZERO_RETURN) {
        tls_error(s, error, saved_errno, "expected_close_notify");
        exit(21);
    }
    printf("{\"event\":\"clean_eof\",\"leg\":\"%s\"}\n", leg(s));
}

static void close_tls(SSL *s, int notify) {
    if (!s) return;
    int fd = SSL_get_fd(s);
    if (notify) {
        ERR_clear_error();
        errno = 0;
        int rc = SSL_shutdown(s), saved_errno = errno;
        if (rc < 0) {
            int error = SSL_get_error(s, rc);
            tls_error(s, error, saved_errno, "shutdown");
            exit(21);
        }
    }
    SSL_free(s);
    close(fd);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, deadline);
    alarm(12);
    require(argc >= 2, "missing role");
    if (!strcmp(argv[1], "version")) {
        printf("headers=%s\nruntime=%s\n", OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION));
        return 0;
    }
    unsigned char buf[CAP], request[CAP];
    size_t len, n;
    if (!strcmp(argv[1], "origin")) {
        require(argc == 7, "origin LISTEN_FD CANCEL_FD GROUPS CERT KEY");
        int fd = accept_one(number(argv[2], INT_MAX), number(argv[3], INT_MAX));
        if (fd < 0) return 0; /* Explicit supervisor cancellation, never a timeout. */
        SSL *s = peer(fd, "backend", argv[4], argv[5], argv[6], NULL, NULL);
        if (!handshake(s)) { close_tls(s, 0); return 20; }
        len = frame(s, request, 0, 0, "request");
        require(len <= CAP - (sizeof(prefix) - 1), "request too large for response");
        memcpy(buf, prefix, sizeof(prefix) - 1);
        memcpy(buf + sizeof(prefix) - 1, request, len);
        frame(s, buf, len + sizeof(prefix) - 1, 1, "response");
        close_tls(s, 1);
    } else if (!strcmp(argv[1], "client")) {
        require(argc == 7, "client PORT GROUPS CA HOST PAYLOAD_FILE");
        FILE *file = fopen(argv[6], "rb");
        require(file != NULL, "payload file");
        n = fread(request, 1, sizeof(request), file);
        require(!ferror(file) && n > 0 && n <= CAP - (sizeof(prefix) - 1) &&
                fgetc(file) == EOF, "payload size/read");
        require(fclose(file) == 0, "payload close");
        SSL *s = peer(dial(number(argv[2], 65535)), "front", argv[3],
                      NULL, NULL, argv[4], argv[5]);
        if (!handshake(s)) { close_tls(s, 0); return 20; }
        frame(s, request, n, 1, "request");
        len = frame(s, buf, 0, 0, "response");
        require(len == n + sizeof(prefix) - 1 && !memcmp(buf, prefix, sizeof(prefix) - 1) &&
                !memcmp(buf + sizeof(prefix) - 1, request, n), "exact response mismatch");
        eof(s);
        printf("{\"event\":\"exact_response_verified\"}\n");
        close_tls(s, 1);
    } else require(0, "unknown role");
    return 0;
}
