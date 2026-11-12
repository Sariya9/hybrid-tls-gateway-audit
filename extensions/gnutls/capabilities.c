#include <stdio.h>
#include <gnutls/gnutls.h>
int main(void) {
    if(gnutls_global_init()!=0) return 1;
    printf("headers=%s\nruntime=%s\n",GNUTLS_VERSION,gnutls_check_version(NULL));
    const gnutls_group_t *g=gnutls_group_list();
    for(;*g;g++) printf("group=%s internal_id=%d\n",gnutls_group_get_name(*g),*g);
    gnutls_priority_t p; const char *err=NULL;
    int rc=gnutls_priority_init(&p,"NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-X25519-MLKEM768:-KX-ALL:+ECDHE-ECDSA",&err);
    printf("hybrid_priority_rc=%d reason=%s\n",rc,gnutls_strerror(rc));
    if(rc==0) gnutls_priority_deinit(p);
    gnutls_global_deinit(); return 0;
}
