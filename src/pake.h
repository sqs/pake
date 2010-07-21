#ifndef TCPCRYPT_PAKE_H
#define TCPCRYPT_PAKE_H

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

#define RESP_LENGTH 64 /* length of hex-encoded SHA256 hash (respc, resps) */

struct pake_public_info {
    EC_GROUP *G;
    EC_POINT *U;
    EC_POINT *V;
    const char     *username;
    const char     *realm;
};

struct pake_shared_info {
    BIGNUM   *pi_0; /* = H_0(user, realm, pw) */
    EC_POINT *L; /* = g^{\pi_0} */

    /* computed values */
    EC_POINT *V_pi_0;
    EC_POINT *U_pi_0;
    EC_POINT *V_minus_pi_0;
    EC_POINT *U_minus_pi_0;

    EC_POINT *N; /* = (Y/V^{\pi_0})^{\pi_1} = L^\beta */
    EC_POINT *Z; /* = (Y/V^{\pi_0})^\alpha = (X/U^{\pi_0})^\beta */

    unsigned char h[SHA256_DIGEST_LENGTH]; /* = H(\pi_0, X, Y, Z, N) */

    unsigned char respc[RESP_LENGTH+1]; /* = H(h, TAG_CLIENT | sid) */
    unsigned char resps[RESP_LENGTH+1]; /* = H(h, TAG_SERVER | sid) */
};

struct pake_client_info {
    const char   *password;
    BIGNUM *pi_1; /* = H_1(user, realm, pw) */
};

struct pake_client_state {
    BIGNUM *alpha;
    EC_POINT *X;

    /* recvd from server */
    EC_POINT *server_Y;
};

struct pake_server_state {
    BIGNUM *beta;
    EC_POINT *Y;

    /* recvd from client */
    EC_POINT *client_X;
};

struct pake_info {
    struct pake_public_info  public;
    struct pake_shared_info  shared;
    struct pake_client_info  client;
    struct pake_client_state client_state;
    struct pake_server_state server_state;
    unsigned isclient;
    unsigned isserver;

    BN_CTX *ctx;
};

struct pake_info *pake_server_new();
struct pake_info *pake_client_new();

int pake_server_init(struct pake_info *p, BIGNUM *beta);
int pake_client_init(struct pake_info *p);

int pake_client_set_credentials(struct pake_info *p, const char *username, const char *realm, const char *password);
int pake_server_set_credentials(struct pake_info *p, const char *username, const char *realm, const BIGNUM *pi_0, const EC_POINT *L);

char *pake_client_get_X_string(struct pake_info *p);
char *pake_server_get_Y_string(struct pake_info *p);

int pake_client_recv_Y(struct pake_info *p, EC_POINT *Y);
int pake_client_recv_Y_string(struct pake_info *p, const char *Y_string);
int pake_server_recv_X(struct pake_info *p, EC_POINT *X);
int pake_server_recv_X_string(struct pake_info *p, const char *X_string);

void pake_free(struct pake_info *p);
void pake_clear(struct pake_info *p);

char *tcpcrypt_pake_compute_resps(struct pake_info *p, unsigned long tcpcrypt_sid);
char *tcpcrypt_pake_compute_respc(struct pake_info *p, unsigned long tcpcrypt_sid);

void debug_pake_info(const struct pake_info *p);

#endif // TCPCRYPT_PAKE_H
