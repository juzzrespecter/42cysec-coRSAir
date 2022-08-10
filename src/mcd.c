#include "corsair.h"

static void clean_ctx(mcd_ctx_t* c)
{
    if (c->r)
        BN_free(c->r);
    if (c->ctx)
        BN_CTX_free(c->ctx);
}

/* impl. of greatest common divisor for RSA modules */
BIGNUM* mcd(const BIGNUM* n1, const BIGNUM* n2)
{
    mcd_ctx_t  c;
    BIGNUM    *r;

    memset(&c, '\0', sizeof(mcd_ctx_t));
    c.r = BN_new();
    c.ctx = BN_CTX_new();
    if (!c.ctx || !c.r)
    {
        clean_ctx(&c);
        return print_fatal("mcd");
    }
    if (!BN_gcd(c.r, n1, n2, c.ctx))
    {
        clean_ctx(&c);
        return print_fatal("BN_gcd");
    }
    if (BN_is_one(c.r))
    {
	clean_ctx(&c);
	printf("provided certs. do not share common prime number (that is actually good)\n");
	return NULL;
    }
#ifdef DEBUG
    printf("~~ ** mcd operations ** ~~\n");
    printf("~~          n1          ~~\n");
    BN_print_fp(stdout, n1);
    printf("\n~~          n2          ~~\n");
    BN_print_fp(stdout, n2);
    printf("\n~~         gcd          ~~\n");
    BN_print_fp(stdout, c.r);
    printf("\n~~ **      end        ** ~~\n");
#endif
    r = BN_dup(c.r);
    clean_ctx(&c);
    return r;
}
