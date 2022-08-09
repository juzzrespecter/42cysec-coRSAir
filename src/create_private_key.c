#include "corsair.h"

static void clear_ctx(cpk_ctx_t* c)
{
    if (c->dv)
        BN_free(c->dv);
    if (c->rem)
        BN_free(c->rem);
    if (c->ctx)
        BN_CTX_free(c->ctx);
}

static BIGNUM* d(const BIGNUM* p, const BIGNUM* q, const BIGNUM* e)
{
    BIGNUM* d = NULL;
    BIGNUM* one = BN_new();
    BIGNUM* mod = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    if (!d || !one || !p_sub || !q_sub || !mod || !ctx)
    {
        printf("you're dead!\n");
    }
    /* controla ret value de esta mierda */
    BN_dec2bn(&one, "1");
    BN_sub(p, p, one);
    BN_sub(q, q, one);
    BN_mul(mod, p, q, ctx);
    d = BN_mod_inverse(NULL, e, mod);
    return d;
}

static cpk_ctx_t* sr

static RSA* create_RSAkey(const BIGNUM* n, const BIGNUM* d)
{
    RSA* rsa = RSA_new();
}

void* /* TMP retval */ cpk(const BIGNUM* n, const BIGNUM* p)
{
    cpk_ctx_t ctx;

    memset(&ctx, '\0', sizeof(cpk_ctx_t));
    ctx.dv = BN_new();
    ctx.rem = BN_new();
    ctx.ctx = BN_CTX_new();
    if (!ctx.dv || !ctx.rem || !ctx.ctx)
    {
        clear_ctx(&ctx);
        return print_fatal("cpk");
    }
        BN_print_fp(stdout, n);
            BN_print_fp(stdout, p);
    if (!BN_div(ctx.dv, ctx.rem, n, p, ctx.ctx))
    {
        clear_ctx(&ctx);
        return print_fatal("BN_div");
    }
    if (!BN_is_zero(ctx.rem))
    {
        clear_ctx(&ctx);
        printf("fatal: could not get second prime number\n");
        return NULL;
    }
    /* dv == q !! */
#ifdef DEBUG
    printf("\n~~ ** cpk operations ** ~~\n");
    printf("~~          q           ~~\n");
    BN_print_fp(stdout, ctx.dv);
    printf("\n~~ **      end        ** ~~\n");
#endif
    d(NULL,NULL);
    return NULL;
}

/* main */
/* get q */
/* get d */
/* get dmp1, dmq1, iqmp */
/* build rsa */
/*write to file */