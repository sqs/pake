#include "pake.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <alloca.h>
#include <openssl/obj_mac.h>
#include <assert.h>

#define SHOW_WORK 1

const unsigned char TCPCRYPT_TAG_CLIENT = 0;
const unsigned char TCPCRYPT_TAG_SERVER = 1;

static int pake_server_init_state(struct pake_info *p, BIGNUM *beta);
static int pake_client_init_state(struct pake_info *p);
static int pake_init_public(struct pake_info *p);

static int pake_compute_h(struct pake_info *p);
static int pake_server_compute_N_Z(struct pake_info *p);
static int pake_client_compute_N_Z(struct pake_info *p);

static char *pake_compute_resp(struct pake_info *p, const char *sessid, int is_resps);

static int get_affine_coordinates(const EC_GROUP *G,
                           const EC_POINT *P,
                           BIGNUM *x,
                           BIGNUM *y,
                           BN_CTX *ctx);
static int hash_bn(SHA256_CTX *sha, const BIGNUM *x);
static int hash_point(SHA256_CTX *sha,
               const EC_GROUP *G,
               const EC_POINT *P,
               BIGNUM *P_x,
               BIGNUM *P_y,
               BN_CTX *ctx);


struct pake_info *pake_server_new() {
    struct pake_info *p;
    p = calloc(1, sizeof(struct pake_info));
    if (!p) goto err;

    if (!(p->ctx = BN_CTX_new())) goto err;
    BN_CTX_start(p->ctx);

    return p;

 err:
    if (p) free(p);
    return NULL;
}

struct pake_info *pake_client_new() {
    return pake_server_new();
}

int pake_server_init(struct pake_info *p, BIGNUM *beta) {
    int ret = 0;

    p->isserver = 1;
    
    if (!pake_init_public(p)) goto err;
    if (!pake_server_init_state(p, beta)) goto err;

    ret = 1;

 err:
    return ret;
}

int pake_client_init(struct pake_info *p) {
    int ret = 0;

    p->isclient = 1;

    if (!pake_init_public(p)) goto err;
    if (!pake_client_init_state(p)) goto err;

    ret = 1;

 err:
    return ret;
}

/* Set $G,$ $U,$ and $V.$ */
int pake_init_public(struct pake_info *p) {
    int ret = 0;
    BIGNUM *tmp = NULL, *order = NULL;

    p->public.G = NULL;
    p->public.U = NULL;
    p->public.V = NULL;

    tmp = BN_new();
    order = BN_new();
    if (!tmp || !order) goto err;

    /* set G */
    p->public.G = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!p->public.G) goto err;
    if (!EC_GROUP_get_order(p->public.G, order, p->ctx)) goto err;
    
    /* alloc U and V */
    p->public.U = EC_POINT_new(p->public.G);
    p->public.V = EC_POINT_new(p->public.G);
    if (!p->public.U || !p->public.V) goto err;

    /* HACK: choose U, V */
    do {
        if (!BN_rand_range(tmp, order)) goto err;
    } while (BN_is_zero(tmp));
    if (!BN_hex2bn(&tmp, "799ABC951C32825396D5EEA12C527308ECC0393621EEFC82B5B2C6AB4BA895B6")) goto err;
    if (!EC_POINT_mul(p->public.G, p->public.U, tmp, NULL, NULL, p->ctx)) goto err;

    do {
        if (!BN_rand_range(tmp, order)) goto err;
    } while (BN_is_zero(tmp));
    if (!BN_hex2bn(&tmp, "7417A0F2C5824875508F1524CAFA2521F49562B89D86D15530BFF792EBBB8BDD")) goto err;
    if (!EC_POINT_mul(p->public.G, p->public.V, tmp, NULL, NULL, p->ctx)) goto err;

    ret = 1;

 err:
    if (!ret) printf("FAIL\n");
    return ret;
}

/* Choose $\beta \in \mathbf{Z}_q$ at random. */
int pake_server_init_state(struct pake_info *p, BIGNUM *beta) {
    int ret = 0;
    BIGNUM *order = NULL;

    order = BN_new();

    if (beta) {
        p->server_state.beta = BN_dup(beta);
    } else {
        p->server_state.beta = BN_new();
        if (!order || !p->server_state.beta) goto err;
        if (!EC_GROUP_get_order(p->public.G, order, p->ctx)) goto err;
    
        /* choose beta */
        do {
            if (!BN_rand_range(p->server_state.beta, order)) goto err;
        } while (BN_is_zero(p->server_state.beta));
        if (!BN_hex2bn(&p->server_state.beta, "7417A0A2C9824875508F1524C28FBA21F49562B89D86D15530BFF792EBBB8BDD")) goto err;
    }
 
    ret = 1;

 err:
    if (order) BN_free(order);
    /* others already free */

    return ret;
}

/* Choose $\beta in \mathbf{Z}_q$ at random, and compute $X=g^\alpha
   U^{\pi_0}.$ */
int pake_client_init_state(struct pake_info *p) {
    int ret = 0;
    BIGNUM *order = NULL;

    order = BN_new();
    p->client_state.alpha = BN_new();
    if (!order || !p->client_state.alpha) goto err;
    if (!EC_GROUP_get_order(p->public.G, order, p->ctx)) goto err;
    
    /* choose alpha */
    do {
        if (!BN_rand_range(p->client_state.alpha, order)) goto err;
    } while (BN_is_zero(p->client_state.alpha));

    ret = 1;

 err:
    if (order) BN_free(order);
    /* others already free */

    return ret;
}

static int pake_common_set_credentials(struct pake_info *p,
                                       const char *username,
                                       const char *realm) {
    if (!username || !realm) return 0;
    if (username[0] == '\0' || realm[0] == '\0') return 0;
    p->public.username = username;
    p->public.realm = realm;
    return 1;
}

static int pake_common_precompute(struct pake_info *p) {
    int ret = 0;
    EC_POINT *tmp = NULL;

    if (!p->shared.pi_0 || !p->public.V || !p->public.U) goto err;

    /* compute V_pi_0 */
    if (!(p->shared.V_pi_0 = EC_POINT_new(p->public.G))) goto err; /* TODO: free this */
    if (!EC_POINT_mul(p->public.G, p->shared.V_pi_0, NULL, p->public.V, p->shared.pi_0, p->ctx)) goto err;

    /* compute U_pi_0 */
    if (!(p->shared.U_pi_0 = EC_POINT_new(p->public.G))) goto err; /* TODO: free this */
    if (!EC_POINT_mul(p->public.G, p->shared.U_pi_0, NULL, p->public.U, p->shared.pi_0, p->ctx)) goto err;

    /* compute U_minus_pi_0 */
    if (!(p->shared.U_minus_pi_0 = EC_POINT_new(p->public.G))) goto err; /* TODO: free this */
    if (!EC_POINT_mul(p->public.G, p->shared.U_minus_pi_0, NULL, p->public.U, p->shared.pi_0, p->ctx)) goto err;
    if (!EC_POINT_invert(p->public.G, p->shared.U_minus_pi_0, p->ctx)) goto err;

    /* compute V_minus_pi_0 */
    if (!(p->shared.V_minus_pi_0 = EC_POINT_new(p->public.G))) goto err; /* TODO: free this */
    if (!EC_POINT_mul(p->public.G, p->shared.V_minus_pi_0, NULL, p->public.V, p->shared.pi_0, p->ctx)) goto err;
    if (!EC_POINT_invert(p->public.G, p->shared.V_minus_pi_0, p->ctx)) goto err;

    /* compute X and Y */
    tmp = EC_POINT_new(p->public.G); /* TODO: free this */
    if (!tmp) goto err;

    if (p->isserver) {
        /* compute Y */
        if (!(p->server_state.Y = EC_POINT_new(p->public.G))) goto err;
        if (!EC_POINT_mul(p->public.G, tmp, p->server_state.beta, NULL, NULL, p->ctx)) goto err;
        if (!EC_POINT_add(p->public.G, p->server_state.Y, tmp, p->shared.V_pi_0, p->ctx)) goto err;    
    }

    if (p->isclient) {
        /* compute X */
        if (!(p->client_state.X = EC_POINT_new(p->public.G))) goto err;
        if (!EC_POINT_mul(p->public.G, tmp, p->client_state.alpha, NULL, NULL, p->ctx)) goto err;
        if (!EC_POINT_add(p->public.G, p->client_state.X, tmp, p->shared.U_pi_0, p->ctx)) goto err;
    }

    ret = 1;

 err:
    return ret;    
}

int pake_client_set_credentials(struct pake_info *p,
                                const char *username, 
                                const char *realm, 
                                const char *password) {
    int ret = 0;
    unsigned char H = 0;
    BIGNUM *tmp = NULL, *order = NULL;
    SHA512_CTX sha;
    unsigned char md[SHA512_DIGEST_LENGTH];

    if (!pake_common_set_credentials(p, username, realm)) goto err;

    order = BN_new();
    tmp = BN_new();
    if (!order || !tmp) goto err;
    if (!EC_GROUP_get_order(p->public.G, order, p->ctx)) goto err;

    /* HACK: make sure we can get ~uniform distribution [bittau] */
    if (BN_num_bits(order) > 512 - 64) goto err;

    /* get pi_0 */
    if (!(p->shared.pi_0 = BN_new())) goto err; /* TODO: free this */
    H = 0;
    if (!SHA512_Init(&sha)) goto err;
    if (!SHA512_Update(&sha, &H, 1)) goto err;
    if (!SHA512_Update(&sha, p->public.username, 1+strlen(p->public.username))) goto err;
    if (!SHA512_Update(&sha, ":", 1)) goto err;
    if (!SHA512_Update(&sha, p->public.realm, 1+strlen(p->public.realm))) goto err;
    if (!SHA512_Update(&sha, ":", 1)) goto err;
    if (!SHA512_Update(&sha, password, 1+strlen(password))) goto err;
    if (!SHA512_Final(md, &sha)) goto err;
    if (!BN_bin2bn(md, sizeof(md), tmp)) goto err;
    if (!BN_nnmod(p->shared.pi_0, tmp, order, p->ctx)) goto err;

    /* get pi_1 */
    if (!(p->client.pi_1 = BN_new())) goto err; /* TODO: free this */
    H = 1;
    if (!SHA512_Init(&sha)) goto err;
    if (!SHA512_Update(&sha, &H, 1)) goto err;
    if (!SHA512_Update(&sha, p->public.username, 1+strlen(p->public.username))) goto err;
    if (!SHA512_Update(&sha, ":", 1)) goto err;
    if (!SHA512_Update(&sha, p->public.realm, 1+strlen(p->public.realm))) goto err;
    if (!SHA512_Update(&sha, ":", 1)) goto err;
    if (!SHA512_Update(&sha, password, 1+strlen(password))) goto err;
    if (!SHA512_Final(md, &sha)) goto err;
    if (!BN_bin2bn(md, sizeof(md), tmp)) goto err;
    if (!BN_nnmod(p->client.pi_1, tmp, order, p->ctx)) goto err;

    if (!pake_common_set_credentials(p, username, realm)) goto err;

    /* compute L */
    if (!(p->shared.L = EC_POINT_new(p->public.G))) goto err; /* TODO: free this */
    if (!EC_POINT_mul(p->public.G, p->shared.L, p->client.pi_1, NULL, NULL, p->ctx)) goto err;

    if (!pake_common_precompute(p)) goto err;

    ret = 1;

 err:
    if (!ret) {
        BN_clear(p->shared.pi_0);
        BN_clear(p->client.pi_1);
    }

    if (order) BN_free(order);
    if (tmp) BN_clear_free(tmp);

    bzero(md, sizeof(md));
    bzero(&sha, sizeof(sha));

    return ret;
}

/* Set $pi_0,$ $pi_1$ (if client), and $L.$ Precompute $V^{\pi_0},$ $U^{\pi_0},$
   $V^{-\pi_0},$ and $U^{-\pi_0}.$ */
int pake_server_set_credentials(struct pake_info *p,
                                const char *username, 
                                const char *realm,
                                const BIGNUM *pi_0,
                                const EC_POINT *L) {
    int ret = 0;

    if (!pake_common_set_credentials(p, username, realm)) goto err;

    if (!pi_0 | !L) goto err;
    p->shared.pi_0 = BN_dup(pi_0);
    p->shared.L = EC_POINT_dup(L, p->public.G);

    if (!pake_common_precompute(p)) goto err;

    ret = 1;

 err:
    return ret;
}

char *pake_client_get_X_string(struct pake_info *p) {
    /* TODO: must OPENSSL_free this string, make it static? same for
       server_get_Y_string */
    return EC_POINT_point2hex(p->public.G, p->client_state.X, POINT_CONVERSION_COMPRESSED, p->ctx);
}

char *pake_server_get_Y_string(struct pake_info *p) {
    return EC_POINT_point2hex(p->public.G, p->server_state.Y, POINT_CONVERSION_COMPRESSED, p->ctx);
}

int pake_client_recv_Y(struct pake_info *p, EC_POINT *Y) {
    p->client_state.server_Y = Y;
    return 1;
}

int pake_client_recv_Y_string(struct pake_info *p, const char *Y_string) {
    EC_POINT *Y = EC_POINT_new(p->public.G);
    EC_POINT_hex2point(p->public.G, Y_string, Y, p->ctx);
    return pake_client_recv_Y(p, Y);
}

int pake_server_recv_X(struct pake_info *p, EC_POINT *X) {
    p->server_state.client_X = X;
    return 1;
}

int pake_server_recv_X_string(struct pake_info *p, const char *X_string) {
    EC_POINT *X = EC_POINT_new(p->public.G);
    EC_POINT_hex2point(p->public.G, X_string, X, p->ctx);
    return pake_server_recv_X(p, X);
}

/* Compute $N = L^\beta$ and $Z = (X/U^{\pi_0})^\beta.$ */
int pake_server_compute_N_Z(struct pake_info *p) {
    int ret = 0;
    EC_POINT *X2 = NULL;

    if (!(X2 = EC_POINT_new(p->public.G))) goto err;

    /* Compute $N = L^\beta.$ */
    if (!EC_POINT_mul(p->public.G, p->shared.N, NULL, p->shared.L, p->server_state.beta, p->ctx)) goto err;
#ifdef SHOW_WORK
    printf("SHOW_WORK: pake_server_compute_N_Z: N = L^beta.\n"
           "N = %s\nL = %s\nbeta=%s\n",
           EC_POINT_point2hex(p->public.G, p->shared.N, POINT_CONVERSION_COMPRESSED, p->ctx),
           EC_POINT_point2hex(p->public.G, p->shared.L, POINT_CONVERSION_COMPRESSED, p->ctx),
           BN_bn2hex(p->server_state.beta));
#endif

    /* Compute $Z = (X/U^{\pi_0})^\beta.$ */
    if (!EC_POINT_add(p->public.G, X2, p->server_state.client_X, p->shared.U_minus_pi_0, p->ctx)) goto err;
    if (!EC_POINT_mul(p->public.G, p->shared.Z, NULL, X2, p->server_state.beta, p->ctx)) goto err;
    
    ret = 1;

 err:
    if (X2) EC_POINT_clear_free(X2); /* TODO: necessary? */

    return ret;
}

/* Compute $N = (Y/V^{\pi_0})^{\pi_1}$ and $Z = (Y/V^{\pi_0})^{\pi_1}.$ */
int pake_client_compute_N_Z(struct pake_info *p) {
    int ret = 0;
    EC_POINT *Y2 = NULL;

    if (!(Y2 = EC_POINT_new(p->public.G))) goto err;

    /* Compute $Y2 = Y/V^{\pi_0}.$ */
    if (!EC_POINT_add(p->public.G, Y2, p->client_state.server_Y, p->shared.V_minus_pi_0, p->ctx)) goto err;

    /* Compute $N = (Y/V^{\pi_0})^{\pi_1} = Y2^{\pi_1}.$ */
    if (!EC_POINT_mul(p->public.G, p->shared.N, NULL, Y2, p->client.pi_1, p->ctx)) goto err;
#ifdef SHOW_WORK
    printf("SHOW_WORK: pake_client_compute_N_Z: N = Y2^{\\pi_1}.\n"
           "N = %s\nY2 = %s\npi_1=%s\n",
           EC_POINT_point2hex(p->public.G, p->shared.N, POINT_CONVERSION_COMPRESSED, p->ctx),
           EC_POINT_point2hex(p->public.G, Y2, POINT_CONVERSION_COMPRESSED, p->ctx),
           BN_bn2hex(p->client.pi_1));
#endif


    /* Compute $Z = (Y/V^{\pi_0})^\alpha = Y2^\alpha.$ */
    if (!EC_POINT_mul(p->public.G, p->shared.Z, NULL, Y2, p->client_state.alpha, p->ctx)) goto err;
    
    ret = 1;

 err:
    if (Y2) EC_POINT_clear_free(Y2); /* TODO: necessary? */

    return ret;    
}

/* Compute $h = H(\pi_0, X, Y, Z, N).$ */
int pake_compute_h(struct pake_info *p) {
    int ret = 0;
    BIGNUM *P_x = NULL, *P_y = NULL;
    SHA256_CTX sha;

    if (!(p->shared.N = EC_POINT_new(p->public.G))) goto err;
    if (!(p->shared.Z = EC_POINT_new(p->public.G))) goto err;
    if (!(P_x = BN_new())) goto err;
    if (!(P_y = BN_new())) goto err;
    if (!SHA256_Init(&sha)) goto err;

    /* First, compute N and Z. */
    if (p->isserver) {
        if (!pake_server_compute_N_Z(p)) goto err;
    } else {
        if (!pake_client_compute_N_Z(p)) goto err;
    }

    /* Now we can compute $h = SHA256(\pi_0, X, Y, Z, N).$ */
    if (!hash_bn(&sha, p->shared.pi_0)) goto err;
    if (!hash_point(&sha, p->public.G, 
                    p->isclient ? p->client_state.X : p->server_state.client_X,
                    P_x, P_y, p->ctx)) goto err;
    if (!hash_point(&sha, p->public.G, 
                    p->isserver ? p->server_state.Y : p->client_state.server_Y,
                    P_x, P_y, p->ctx)) goto err;
    if (!hash_point(&sha, p->public.G, p->shared.Z, P_x, P_y, p->ctx)) goto err;
    if (!hash_point(&sha, p->public.G, p->shared.N, P_x, P_y, p->ctx)) goto err;    
    if (!SHA256_Final(p->shared.h, &sha)) goto err;
    
    ret = 1;

 err:
    if (P_x) BN_clear_free(P_x);
    if (P_y) BN_clear_free(P_y);

    bzero(&sha, sizeof(sha));

    return ret;
}

/* Compute $resps = H(h, TAG_SERVER | sid).$ */
char *pake_compute_resps(struct pake_info *p, const char *sessid) {
    return pake_compute_resp(p, sessid, 1);
}

/* Compute $respc = H(h, TAG_CLIENT | sid). */
char *pake_compute_respc(struct pake_info *p, const char *sessid) {
    return pake_compute_resp(p, sessid, 0);
}

/* Expects sessid is a hex string of the session ID. */
char *pake_compute_resp(struct pake_info *p, const char *sessid, int is_resps) {
    int ret = 0;
    const char *hex = "0123456789ABCDEF";
    unsigned char resp[SHA256_DIGEST_LENGTH];
    unsigned char *s, *orig_s;
    unsigned char tag;
    SHA256_CTX sha;

    if (!pake_compute_h(p)) goto err;

    tag = is_resps ? TCPCRYPT_TAG_SERVER : TCPCRYPT_TAG_CLIENT;

    if (!SHA256_Init(&sha)) goto err;
    if (!SHA256_Update(&sha, p->shared.h, sizeof(p->shared.h))) goto err;
    /* TODO: make sessid length a constant */
    if (sessid && !SHA256_Update(&sha, sessid, strnlen(sessid, 512))) goto err; 
    if (!SHA256_Update(&sha, &tag, sizeof(tag))) goto err;
    if (!SHA256_Final(resp, &sha)) goto err;

    /* convert to hex */
    int i = 0;
    orig_s = s = is_resps ? p->shared.resps : p->shared.respc;
    for (i=0; i < SHA256_DIGEST_LENGTH; ++i) {
        *(s++) = hex[resp[i] >> 4];
        *(s++) = hex[resp[i] & 0xF];
    }
    *s++ = '\0';

    ret = 1;

#ifdef SHOW_WORK
    printf("SHOW_WORK: pake_compute_resp: resp%c = SHA256(h, TAG | sid)\n"
           "h = %s\nsessid = %s\nstrlen(sessid)=%zu\n",
           is_resps ? 's' : 'c',
           p->shared.h,
           sessid,
           strnlen(sessid, 512));
#endif

    goto err;

 err:
    
    bzero(&sha, sizeof(sha));
    
    if (ret) return (char *)orig_s;
    else return NULL;
}

void pake_free(struct pake_info *p) {
    BN_CTX_end(p->ctx);
    BN_CTX_free(p->ctx);    
}

void pake_clear(struct pake_info *p) {
    memset(p, 0, sizeof(struct pake_info));
}

void debug_pake_info(const struct pake_info *p) {
    const char *t = "\t";

    printf("struct pake_info {\n");
    
    /* public */
    printf("%sEC_GROUP G     = %s\n", t,     "<...>");
    printf("%sEC_POINT U     = %s\n", t,     "<...>");
    printf("%sEC_POINT V     = %s\n", t,     "<...>");
    printf("%schar *username = \"%s\"\n", t, p->public.username);
    printf("%schar *realm    = \"%s\"\n", t, p->public.realm);

    printf("\n%s/*** pake_shared_info ***/\n", t);
    printf("%spi_0 =  %s\n", t, BN_bn2hex(p->shared.pi_0));
    printf("%sL    = %s\n", t, EC_POINT_point2hex(p->public.G, p->shared.L, POINT_CONVERSION_COMPRESSED, NULL));
    printf("\n");
    printf("%sV_pi_0 = %s\n", t, EC_POINT_point2hex(p->public.G, p->shared.V_pi_0, POINT_CONVERSION_COMPRESSED, NULL));
    printf("%sU_pi_0 = %s\n", t, EC_POINT_point2hex(p->public.G, p->shared.U_pi_0, POINT_CONVERSION_COMPRESSED, NULL));
    printf("%sV_-pi_0= %s\n", t, EC_POINT_point2hex(p->public.G, p->shared.V_minus_pi_0, POINT_CONVERSION_COMPRESSED, NULL));
    printf("%sU_-pi_0= %s\n", t, EC_POINT_point2hex(p->public.G, p->shared.U_minus_pi_0, POINT_CONVERSION_COMPRESSED, NULL));
    printf("\n");
    printf("%sN    = %s\n", t, p->shared.N ? EC_POINT_point2hex(p->public.G, p->shared.N, POINT_CONVERSION_COMPRESSED, NULL) : "null");
    printf("%sZ    = %s\n", t, p->shared.Z ? EC_POINT_point2hex(p->public.G, p->shared.Z, POINT_CONVERSION_COMPRESSED, NULL) : "null");
    printf("%sh    = %*s\n", t, SHA256_DIGEST_LENGTH, p->shared.h);
    printf("%srespc= %*s\n", t, RESP_LENGTH+1, p->shared.respc);
    printf("%sresps= %*s\n", t, RESP_LENGTH+1, p->shared.resps);

    if (p->isclient) {
        printf("\n%s/*** pake_client_info ***/\n", t);
        printf("%spassword = \"%s\"\n", t, p->client.password);
        printf("%spi_1     =  %s\n", t, BN_bn2hex(p->client.pi_1));

        printf("\n%s/*** pake_client_state ***/\n", t);
        printf("%salpha = %s\n", t, BN_bn2hex(p->client_state.alpha));
        printf("%sX = %s\n", t, EC_POINT_point2hex(p->public.G, p->client_state.X, POINT_CONVERSION_COMPRESSED, NULL));
        printf("%ssrv_Y = %s\n", t, EC_POINT_point2hex(p->public.G, p->client_state.server_Y, POINT_CONVERSION_COMPRESSED, NULL));
    }

    if (p->isserver) {
        printf("\n%s/*** pake_server_state ***/\n", t);
        printf("%sbeta =  %s\n", t, BN_bn2hex(p->server_state.beta));;
        printf("%sY    = %s\n", t, EC_POINT_point2hex(p->public.G, p->server_state.Y, POINT_CONVERSION_COMPRESSED, NULL));
        printf("%scli_X= %s\n", t, p->server_state.client_X ? EC_POINT_point2hex(p->public.G, p->server_state.client_X, POINT_CONVERSION_COMPRESSED, NULL) : "null");
    }

    printf("\n}\n");
}

static int get_affine_coordinates(const EC_GROUP *G,
                           const EC_POINT *P,
                           BIGNUM *x,
                           BIGNUM *y,
                           BN_CTX *ctx) {
  if (EC_METHOD_get_field_type(EC_GROUP_method_of(G))
      == NID_X9_62_prime_field) {
    return EC_POINT_get_affine_coordinates_GFp (G, P, x, y, ctx);
  } else { /* NID_X9_62_characteristic_two_field */
    return EC_POINT_get_affine_coordinates_GF2m(G, P, x, y, ctx);
  }
}

static int hash_bn(SHA256_CTX *sha, const BIGNUM *x) {
  /* allocate space */
  int size = BN_num_bytes(x), ret = 0;
  if (size <= 0 || size >= 256) return 0;
  unsigned char *tmp = (unsigned char *) alloca(size+1);

  /* first byte is size to ensure parseability */
  *tmp = (unsigned char) size;

  /* convert to bytes and hash it */
  if (!BN_bn2bin(x, tmp+1)) goto err;
  ret = SHA256_Update(sha, (const void *) tmp, size+1);

 err:
  bzero(tmp, size+1);
  return ret;
}

static int hash_point(SHA256_CTX *sha,
               const EC_GROUP *G,
               const EC_POINT *P,
               BIGNUM *P_x,
               BIGNUM *P_y,
               BN_CTX *ctx) {
  int ret = get_affine_coordinates(G, P, P_x, P_y, ctx);
  if (ret) ret = hash_bn(sha, P_x);
  if (ret) ret = hash_bn(sha, P_y);
  return ret;
}
