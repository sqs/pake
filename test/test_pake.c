#include "test_pake.h"
#include "pake.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

void test_pake() {
    struct pake_info *ps, *pc;
    assert(ps = pake_server_new());
    assert(pc = pake_client_new());
    
    assert(pake_server_init(ps, NULL));
    assert(pake_client_init(pc));

    /* set credentials */
    assert(pake_client_set_credentials(pc, "jsmith", "protected area", "jsmith"));
    assert(pake_server_set_credentials(ps, "jsmith", "protected area", pc->shared.pi_0, pc->shared.L));
    
    char *X_string = EC_POINT_point2hex(pc->public.G, pc->client_state.X, POINT_CONVERSION_UNCOMPRESSED, pc->ctx);
    pake_server_recv_X_string(ps, X_string);

    char *Y_string = EC_POINT_point2hex(ps->public.G, ps->server_state.Y, POINT_CONVERSION_UNCOMPRESSED, ps->ctx);
    pake_client_recv_Y_string(pc, Y_string);
    
    /* TODO: HACK: fake tcpcrypt sid */
    unsigned long sid = 123456789;
    assert(strlen(tcpcrypt_pake_compute_resps(ps, sid)));
    assert(strlen(tcpcrypt_pake_compute_respc(ps, sid)));
    assert(strlen(tcpcrypt_pake_compute_resps(pc, sid)));
    assert(strlen(tcpcrypt_pake_compute_respc(pc, sid)));
    
    /* debug_point(ps->public.G, "server N", ps->shared.N); */
    /* debug_point(pc->public.G, "client N", pc->shared.N); */
    /* debug_point(ps->public.G, "server Z", ps->shared.Z); */
    /* debug_point(pc->public.G, "client Z", pc->shared.Z); */

    assert(EC_POINT_cmp(ps->public.G, ps->shared.N, pc->shared.N, ps->ctx) == 0);
    assert(EC_POINT_cmp(ps->public.G, ps->shared.Z, pc->shared.Z, ps->ctx) == 0);

    assert(ps->shared.h[0] && pc->shared.h[0]);
    assert(strncmp((char *)ps->shared.h, (char *)pc->shared.h, SHA256_DIGEST_LENGTH) == 0);
    
    assert(strlen((char *)ps->shared.resps));
    assert(strlen((char *)ps->shared.respc));
    assert(strlen((char *)pc->shared.resps));
    assert(strlen((char *)pc->shared.respc));

    assert(strncmp((char *)ps->shared.resps, (char *)pc->shared.resps, RESP_LENGTH) == 0);
    assert(strncmp((char *)ps->shared.respc, (char *)pc->shared.respc, RESP_LENGTH) == 0);
    assert(strncmp((char *)ps->shared.resps, (char *)ps->shared.respc, RESP_LENGTH) != 0); /* shouldn't be equal - this will fail once per universe */
    
    pake_free(ps);
    pake_free(pc);
    pake_clear(ps);
    pake_clear(pc);
}

int main(int argc, char **argv) {
    printf("*** test_pake\n");
    test_pake();
    printf("PASS\n");
    return 0;
}

