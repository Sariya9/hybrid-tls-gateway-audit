/* Native GnuTLS adapter for the bounded ICETE loopback exchange.
 * Socket supervision, framing and application roles adapt ../proxy_probe.c.
 * shortcut: fixed 4096-byte frames and blocking I/O are for one local exchange;
 * use an event loop before testing concurrency or uncooperative clients.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#define CAP 4096
static const unsigned char prefix[] = "origin-response\0";
static const unsigned char ready[] = "READY";
typedef struct { gnutls_session_t tls; gnutls_certificate_credentials_t cred;
    int fd, server, verified, verify_called; unsigned verify_code;
    const char *which, *host; } Peer;
static void require(int ok, const char *why) {
    if (!ok) { fprintf(stderr, "probe error: %s (errno=%d)\n", why, errno); exit(22); }
}
static void deadline(int sig) {
    (void)sig; static const char msg[]="process deadline exceeded\n";
    (void)write(2,msg,sizeof(msg)-1); _exit(124);
}
static int number(const char *text, int max) {
    char *end; errno=0; long n=strtol(text,&end,10);
    require(!errno && end!=text && !*end && n>=0 && n<=max,"number"); return (int)n;
}
static const char *leg(const Peer *s) { return s->which; }
static void hex(const unsigned char *p, size_t n) { for(size_t i=0;i<n;i++) printf("%02x",p[i]); }
static size_t u16(const unsigned char *p) { return (size_t)p[0]*256+p[1]; }
/* Observe the wire ClientHello body; refuse PSKs independently of configured credentials. */
static int hook(gnutls_session_t tls,unsigned type,unsigned when,unsigned incoming,const gnutls_datum_t *msg) {
    if ((incoming && when!=GNUTLS_HOOK_PRE)||(!incoming && when!=GNUTLS_HOOK_POST)) return 0;
    Peer *s=gnutls_session_get_ptr(tls);
    printf("{\"event\":\"handshake_message\",\"leg\":\"%s\",\"direction\":\"%s\",\"type\":%u}\n",leg(s),incoming?"received":"sent",type);
    if(type==GNUTLS_HANDSHAKE_HELLO_RETRY_REQUEST) printf("{\"event\":\"hello_retry_request\",\"leg\":\"%s\",\"direction\":\"%s\"}\n",leg(s),incoming?"received":"sent");
    if(type!=GNUTLS_HANDSHAKE_CLIENT_HELLO || !incoming || !s->server) return 0;
    const unsigned char *p=msg->data; size_t n=msg->size, i=34;
    require(n>i,"short ClientHello"); size_t k=p[i++]; require(k<=n-i,"session id"); i+=k;
    require(n-i>=2,"cipher length"); k=u16(p+i); i+=2; require(k<=n-i,"ciphers"); i+=k;
    require(n-i>=1,"compression length"); k=p[i++]; require(k<=n-i,"compression"); i+=k;
    require(n-i>=2,"extensions length"); k=u16(p+i); i+=2; require(k==n-i,"extension vector");
    int groups=0,shares=0,psk=0;
    while(i<n) {
        require(n-i>=4,"extension header"); size_t id=u16(p+i),len=u16(p+i+2); i+=4;
        require(len<=n-i,"extension length"); const unsigned char *v=p+i;
        if(id==41) psk=1;
        if(id==10 || id==51) {
            require(len>=2 && u16(v)==len-2,"extension vector length");
            printf("{\"event\":\"%s\",\"leg\":\"%s\",\"iana_ids\":[",id==10?"offered_groups":"offered_key_shares",leg(s));
            size_t j=2,count=0;
            while(j<len) {
                require(len-j>=2,"group entry"); unsigned g=(unsigned)u16(v+j); j+=2;
                printf("%s%u",count++?",":"",g);
                if(id==51) { require(len-j>=2,"share length"); size_t l=u16(v+j); j+=2; require(l<=len-j,"share body"); j+=l; }
            }
            puts("]}"); if(id==10) groups++; else shares++;
        }
        i+=len;
    }
    printf("{\"event\":\"client_hello\",\"leg\":\"%s\",\"psk_offered\":%s}\n",leg(s),psk?"true":"false");
    require(groups==1 && shares==1,"ClientHello group/share extensions");
    return psk?GNUTLS_E_ILLEGAL_PARAMETER:0;
}
static int verify(gnutls_session_t tls) {
    Peer *s=gnutls_session_get_ptr(tls); unsigned status=0,count=0;
    int rc=gnutls_certificate_verify_peers3(tls,s->host,&status);
    const gnutls_datum_t *chain=gnutls_certificate_get_peers(tls,&count);
    gnutls_x509_crt_t crt; require(gnutls_x509_crt_init(&crt)==0,"cert init");
    int san_ok=0,purpose_ok=0;
    if(chain && count && gnutls_x509_crt_import(crt,chain,GNUTLS_X509_FMT_DER)>=0) {
        purpose_ok=gnutls_x509_crt_check_key_purpose(crt,GNUTLS_KP_TLS_WWW_SERVER,0);
        for(unsigned i=0;;i++) {
            char value[512]; size_t len=sizeof(value);
            int type=gnutls_x509_crt_get_subject_alt_name(crt,i,value,&len,NULL);
            if(type==GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) break;
            if(type==GNUTLS_SAN_DNSNAME && len==strlen(s->host) && !memcmp(value,s->host,len)) san_ok=1;
            if(type<0) break;
        }
    }
    gnutls_x509_crt_deinit(crt);
    if(!san_ok) status|=GNUTLS_CERT_UNEXPECTED_OWNER;
    if(!purpose_ok) status|=GNUTLS_CERT_PURPOSE_MISMATCH;
    s->verify_called=1; s->verify_code=status; s->verified=(rc==0 && status==0);
    printf("{\"event\":\"verification\",\"leg\":\"%s\",\"hostname\":\"%s\",\"status\":%u,\"san_exact\":%s,\"server_purpose\":%s,\"rc\":%d}\n",leg(s),s->host,status,san_ok?"true":"false",purpose_ok?"true":"false",rc);
    return s->verified?0:GNUTLS_E_CERTIFICATE_ERROR;
}
static void tls_error(Peer *s,int rc,const char *stage) {
    printf("{\"event\":\"tls_error\",\"leg\":\"%s\",\"stage\":\"%s\",\"gnutls_rc\":%d,\"reason\":\"%s\",\"verify_code\":%u,\"last_alert\":%d}\n",leg(s),stage,rc,rc?gnutls_strerror(rc):"clean EOF",s->verify_code,gnutls_alert_get(s->tls));
    if(rc<0) fprintf(stderr,"GnuTLS %s %s: %s (%d)\n",leg(s),stage,gnutls_strerror(rc),rc);
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
        puts("{\"event\":\"origin_cancelled_before_accept\"}");
        close(listener);
        close(cancel);
        return -1;
    }
    int fd = accept(listener, NULL, NULL);
    close(listener);
    if (cancel >= 0) close(cancel);
    puts("{\"event\":\"accepted\"}");
    return timed_socket(fd);
}


static Peer *peer(int fd,const char *which,const char *groups,const char *cert,const char *key,const char *ca,const char *host) {
    Peer *s=calloc(1,sizeof(*s)); require(s!=NULL,"peer allocation");
    s->fd=fd; s->which=which; s->host=host; s->server=cert!=NULL;
    require(gnutls_certificate_allocate_credentials(&s->cred)==0,"credentials");
    if(s->server) require(gnutls_certificate_set_x509_key_file(s->cred,cert,key,GNUTLS_X509_FMT_PEM)==0,"server certificate/key");
    else {
        require(gnutls_certificate_set_x509_trust_file(s->cred,ca,GNUTLS_X509_FMT_PEM)>0,"explicit CA");
        gnutls_certificate_set_verify_flags(s->cred,GNUTLS_VERIFY_DO_NOT_ALLOW_WILDCARDS);
    }
    require(gnutls_init(&s->tls,(s->server?GNUTLS_SERVER:GNUTLS_CLIENT)|GNUTLS_NO_TICKETS|GNUTLS_NO_AUTO_SEND_TICKET)==0,"session init");
    gnutls_session_set_ptr(s->tls,s);
    const char *suffix=NULL;
    if(!strcmp(groups,"X25519MLKEM768")) suffix="+GROUP-X25519-MLKEM768";
    else if(!strcmp(groups,"X25519")) suffix="+GROUP-X25519";
    else if(!strcmp(groups,"X25519MLKEM768:X25519")) suffix="+GROUP-X25519-MLKEM768:+GROUP-X25519";
    require(suffix!=NULL,"unsupported group list");
    char priority[256]; snprintf(priority,sizeof(priority),"NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:%s:-KX-ALL:+ECDHE-ECDSA",suffix);
    printf("{\"event\":\"tls_configuration\",\"leg\":\"%s\",\"priority\":\"%s\",\"tickets\":false,\"saved_sessions\":false,\"early_data\":false}\n",leg(s),priority);
    const char *err=NULL; int rc=gnutls_priority_set_direct(s->tls,priority,&err);
    if(rc<0) fprintf(stderr,"priority failure %s at %s\n",gnutls_strerror(rc),err?err:"");
    require(rc==0,"TLS priority");
    require(gnutls_credentials_set(s->tls,GNUTLS_CRD_CERTIFICATE,s->cred)==0,"set credentials");
    gnutls_handshake_set_hook_function(s->tls,GNUTLS_HANDSHAKE_ANY,GNUTLS_HOOK_BOTH,hook);
    gnutls_transport_set_int(s->tls,fd);
    gnutls_handshake_set_timeout(s->tls,3000);
    if(!s->server) {
        const char *sni=!strcmp(which,"backend")?"origin.test":"proxy.test";
        require(host && *host,"expected host");
        require(gnutls_server_name_set(s->tls,GNUTLS_NAME_DNS,sni,strlen(sni))==0,"SNI");
        gnutls_session_set_verify_function(s->tls,verify);
    }
    return s;
}
static int handshake(Peer *s) {
    int rc; do { rc=gnutls_handshake(s->tls); } while(rc==GNUTLS_E_INTERRUPTED || rc==GNUTLS_E_AGAIN);
    const char *group=gnutls_group_get_name(gnutls_group_get(s->tls));
    if(rc<0) {
        tls_error(s,rc,"handshake");
        if(rc!=GNUTLS_E_FATAL_ALERT_RECEIVED && rc!=GNUTLS_E_WARNING_ALERT_RECEIVED) {
            int level=0; int alert=gnutls_error_to_alert(rc,&level);
            int sent=gnutls_alert_send_appropriate(s->tls,rc);
            printf("{\"event\":\"alert_sent\",\"leg\":\"%s\",\"level\":%d,\"description\":%d,\"rc\":%d}\n",leg(s),level,alert,sent);
        }
    }
    printf("{\"event\":\"handshake\",\"leg\":\"%s\",\"ok\":%s,\"protocol\":\"%s\",\"group\":\"%s\",\"group_id\":%d,\"session_reused\":%s,\"verify_code\":%u,\"verify_called\":%s,\"certificate_status\":\"%s\",\"verified_hostname\":\"%s\"}\n",leg(s),rc==0?"true":"false",gnutls_protocol_get_name(gnutls_protocol_get_version(s->tls)),group?group:"none",gnutls_group_get(s->tls),gnutls_session_is_resumed(s->tls)?"true":"false",s->verify_code,s->verify_called?"true":"false",s->server?"client_auth_not_requested":s->verified?"verified":"not_verified",s->verified?s->host:"none");
    if(!s->server) {
        unsigned count=0; const gnutls_datum_t *chain=gnutls_certificate_get_peers(s->tls,&count);
        if(chain && count) {
            unsigned char digest[32]; size_t n=sizeof(digest);
            require(gnutls_fingerprint(GNUTLS_DIG_SHA256,chain,digest,&n)==0,"fingerprint");
            printf("{\"event\":\"certificate\",\"leg\":\"%s\",\"kind\":\"peer\",\"sha256\":\"",leg(s)); hex(digest,n); puts("\"}");
        }
    }
    if(rc==0) {
        require(gnutls_protocol_get_version(s->tls)==GNUTLS_TLS1_3 && !gnutls_session_is_resumed(s->tls) && group,"full TLS1.3");
        require(s->server || (s->verified && s->verify_called),"verified server required");
    }
    return rc==0;
}
static void transfer(Peer *s, void *buf, size_t len, int writing,
                     const char *kind, const char *part) {
    unsigned char *p = buf;
    while (len) {
        /* Short writes exercise framing across multiple TLS records. */
        size_t chunk = writing && len > 37 ? 37 : len;
        ssize_t rc;
        do { rc = writing ? gnutls_record_send(s->tls, p, chunk) : gnutls_record_recv(s->tls, p, chunk); }
        while (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN);
        if (rc <= 0) { tls_error(s, (int)rc, writing ? "write" : "read"); exit(21); }
        size_t done = (size_t)rc;
        require(done > 0 && done <= len, "TLS I/O progress");
        if (writing)
            printf("{\"event\":\"write_progress\",\"leg\":\"%s\","
                   "\"kind\":\"%s\",\"part\":\"%s\",\"bytes\":%zu}\n",
                   leg(s), kind, part, done);
        p += done;
        len -= done;
    }
}

static size_t frame(Peer *s, unsigned char *buf, size_t len, int writing, const char *kind) {
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

static void eof(Peer *s) {
    unsigned char extra;
    ssize_t rc = gnutls_record_recv(s->tls, &extra, 1);
    if (rc != 0) { tls_error(s, (int)rc, "expected_close_notify"); exit(21); }
    printf("{\"event\":\"clean_eof\",\"leg\":\"%s\"}\n", leg(s));
}
static void close_tls(Peer *s, int notify) {
    if (!s) return;
    if (notify) {
        int rc = gnutls_bye(s->tls, GNUTLS_SHUT_WR);
        printf("{\"event\":\"shutdown\",\"leg\":\"%s\",\"notify\":true,\"rc\":%d}\n", leg(s), rc);
        require(rc >= 0, "close_notify failed");
    }
    gnutls_deinit(s->tls); gnutls_certificate_free_credentials(s->cred);
    close(s->fd); free(s);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, deadline);
    alarm(12);
    require(argc >= 2, "missing role");
    if (!strcmp(argv[1], "version")) {
        printf("headers=%s\nruntime=%s\n", GNUTLS_VERSION, gnutls_check_version(NULL));
        return 0;
    }
    require(gnutls_global_init() == 0, "GnuTLS global init");
    unsigned char buf[CAP], request[CAP];
    size_t len, n;
    if (!strcmp(argv[1], "origin")) {
        require(argc == 7, "origin LISTEN_FD CANCEL_FD GROUPS CERT KEY");
        int fd = accept_one(number(argv[2], INT_MAX), number(argv[3], INT_MAX));
        if (fd < 0) return 0; /* Explicit supervisor cancellation, never a timeout. */
        Peer *s = peer(fd, "backend", argv[4], argv[5], argv[6], NULL, NULL);
        if (!handshake(s)) { close_tls(s, 0); return 20; }
        len = frame(s, request, 0, 0, "request");
        require(len <= CAP - (sizeof(prefix) - 1), "request too large for response");
        memcpy(buf, prefix, sizeof(prefix) - 1);
        memcpy(buf + sizeof(prefix) - 1, request, len);
        frame(s, buf, len + sizeof(prefix) - 1, 1, "response");
        close_tls(s, 1);
    } else if (!strcmp(argv[1], "proxy")) {
        require(argc == 11, "proxy LISTEN_FD PORT FRONT_GROUPS BACK_GROUPS CERT KEY CA HOST GUARD_MASK");
        Peer *front = peer(accept_one(number(argv[2], INT_MAX), -1), "front", argv[4],
                          argv[6], argv[7], NULL, NULL);
        if (!handshake(front)) { close_tls(front, 0); return 20; }
        Peer *back = peer(dial(number(argv[3], 65535)), "backend", argv[5],
                         NULL, NULL, argv[8], argv[9]);
        if (!handshake(back)) {
            close_tls(back, 0);
            close_tls(front, 1);
            return 20;
        }
        int mask = number(argv[10], 3);
        int front_h = !strcmp(gnutls_group_get_name(gnutls_group_get(front->tls)), "X25519-MLKEM768");
        int back_h = !strcmp(gnutls_group_get_name(gnutls_group_get(back->tls)), "X25519-MLKEM768");
        int allowed = (!(mask & 1) || front_h) && (!(mask & 2) || back_h);
        printf("{\"event\":\"release_policy\",\"guard_mask\":%d,"
               "\"front_hybrid\":%s,\"backend_hybrid\":%s,\"allowed\":%s}\n",
               mask, front_h ? "true" : "false", back_h ? "true" : "false",
               allowed ? "true" : "false");
        if (!allowed) {
            close_tls(back, 1);
            close_tls(front, 1);
            return 23;
        }
        memcpy(buf, ready, sizeof(ready) - 1);
        frame(front, buf, sizeof(ready) - 1, 1, "ready");
        len = frame(front, buf, 0, 0, "request");
        frame(back, buf, len, 1, "request");
        len = frame(back, buf, 0, 0, "response");
        eof(back);
        close_tls(back, 1);
        frame(front, buf, len, 1, "response");
        close_tls(front, 1);
    } else if (!strcmp(argv[1], "client")) {
        require(argc == 7, "client PORT GROUPS CA HOST PAYLOAD_FILE");
        FILE *file = fopen(argv[6], "rb");
        require(file != NULL, "payload file");
        n = fread(request, 1, sizeof(request), file);
        require(!ferror(file) && n > 0 && n <= CAP - (sizeof(prefix) - 1) &&
                fgetc(file) == EOF, "payload size/read");
        require(fclose(file) == 0, "payload close");
        Peer *s = peer(dial(number(argv[2], 65535)), "front", argv[3],
                      NULL, NULL, argv[4], argv[5]);
        if (!handshake(s)) { close_tls(s, 0); return 20; }
        len = frame(s, buf, 0, 0, "ready");
        require(len == sizeof(ready) - 1 && !memcmp(buf, ready, len), "backend ready");
        frame(s, request, n, 1, "request");
        len = frame(s, buf, 0, 0, "response");
        require(len == n + sizeof(prefix) - 1 && !memcmp(buf, prefix, sizeof(prefix) - 1) &&
                !memcmp(buf + sizeof(prefix) - 1, request, n), "exact response mismatch");
        eof(s);
        puts("{\"event\":\"exact_response_verified\"}");
        close_tls(s, 1);
    } else require(0, "unknown role");
    return 0;
}
