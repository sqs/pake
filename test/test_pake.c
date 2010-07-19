#include "test_pake.h"
#include "pake.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/bn.h>

void test_pake() {
    struct pake_info ps, pc;
    BN_CTX *ctx = NULL;

    memset(&ps, 0, sizeof(ps));
    memset(&pc, 0, sizeof(pc));
    assert(ctx = BN_CTX_new());
    BN_CTX_start(ctx);

    assert(pake_server_init(&ps, ctx, NULL));
    assert(pake_client_init(&pc, ctx));

    /* set credentials */
    assert(pake_client_set_credentials(&pc, "jsmith", "protected area", "jsmith", ctx));
    /* TODO: HACK: fake client-server interaction */
    ps.server_state.client_X = pc.client_state.X;
    assert(pake_server_set_credentials(&ps, "jsmith", "protected area", pc.shared.pi_0, pc.shared.L, ctx));
    pc.client_state.server_Y = ps.server_state.Y;
    
    assert(pake_compute_h(&ps, ctx));
    assert(pake_compute_h(&pc, ctx));

    /* debug_point(ps.public.G, "server N", ps.shared.N, ctx); */
    /* debug_point(pc.public.G, "client N", pc.shared.N, ctx); */
    /* debug_point(ps.public.G, "server Z", ps.shared.Z, ctx); */
    /* debug_point(pc.public.G, "client Z", pc.shared.Z, ctx); */

    assert(EC_POINT_cmp(ps.public.G, ps.shared.N, pc.shared.N, ctx) == 0);
    assert(EC_POINT_cmp(ps.public.G, ps.shared.Z, pc.shared.Z, ctx) == 0);

    assert(ps.shared.h[0] && pc.shared.h[0]);
    assert(strncmp((char *)ps.shared.h, (char *)pc.shared.h, SHA256_DIGEST_LENGTH) == 0);

    /* TODO: HACK: fake tcpcrypt sid */
    unsigned long sid = 123456789;
    assert(tcpcrypt_pake_compute_resps(&ps, sid, ctx));
    assert(tcpcrypt_pake_compute_respc(&ps, sid, ctx));
    assert(tcpcrypt_pake_compute_resps(&pc, sid, ctx));
    assert(tcpcrypt_pake_compute_respc(&pc, sid, ctx));
    
    assert(strncmp((char *)ps.shared.resps, (char *)pc.shared.resps, RESP_LENGTH) == 0);
    assert(strncmp((char *)ps.shared.respc, (char *)pc.shared.respc, RESP_LENGTH) == 0);
    assert(strncmp((char *)ps.shared.resps, (char *)ps.shared.respc, RESP_LENGTH) != 0); /* shouldn't be equal - this will fail once per universe */

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

int main(int argc, char **argv) {
    printf("*** test_pake\n");
    test_pake();
    return 0;
}
