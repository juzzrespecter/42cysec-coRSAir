#include "corsair.h"

static void clear_ctx(gpk_ctx_t* c)
{
    if(c->bn_aux_1)
	BN_free(c->bn_aux_1);
    if(c->bn_aux_2)
	BN_free(c->bn_aux_2);
    if(c->p)
	BN_free(c->p);
    if(c->q)	
	BN_free(c->q);
    if(c->d)
	BN_free(c->d);	
    if(c->p_sub)
	BN_free(c->p_sub);	
    if(c->q_sub)
	BN_free(c->q_sub);	
    if(c->one)
	BN_free(c->one);
    if (c->mod)
	BN_free(c->mod);
    if(c->dP)
	BN_free(c->bn_aux_1);	
    if(c->dQ)
	BN_free(c->bn_aux_1);	
    if(c->qInv)
	BN_free(c->bn_aux_1);	
    if(c->ctx)
	BN_CTX_free(c->bn_aux_1);	
}

static BIGNUM* d(gpk_ctx_t* c)
{
    /* controla ret value de esta mierda */
    BN_dec2bn(&c->one, "1");
    BN_sub(c->p_sub, p, one);
    BN_sub(c->q_sub, q, one);
    BN_mul(mod, p_sub, q_suv, ctx);
    d = BN_mod_inverse(NULL, e, mod);
    return d;
}

static BIGNUM* q(const BIGNUM* n, gpk_ctx_t* c)
{
    if (!BN_div(c->q, c->bn_aux_1, n, c->p, c->ctx))
    {
        clear_ctx(&ctx);
        return print_fatal("BN_div");
    }
    if (!BN_is_zero(c->bn_aux_1))
    {
        clear_ctx(&ctx);
        printf("fatal: could not get second prime number\n");
        return NULL;
    }
    return c->q;
}

static gpk_ctx_t* build_params(BIGNUM* e, gpk_ctx_t* c)
{
    c->dP = BN_mod_inverse(NULL, e, c->p_sub);
    c->dQ = BN_mod_inverse(NULL, e, c->q_sub);
    c->qInv = BN_mod_inverse(NULL, c->q, c->p);
    if (!c->dP || !c->dQ || !c->qInv)
	return fatal_print("BN_mod_inverse");
    return c;
}

RSA* gen_priv_key(BIGNUM* ne[2], gpk_ctx_t* c)
{
    RSA* rsa = RSA_new();
    
    RSA_set0_key(c->rsa, ne[0], ne[1], c->d);
    RSA_set0_factors(c->rsa, c->p, c->q);
    RSA_set0_crt_params(c->rsa, c->dP, c->dQ, c->qInv);
    return rsa;
}

RSA* gpk(const BIGNUM* ne[2], const BIGNUM* n2)
{
    cpk_ctx_t c;
    
    memset(&ctx, '\0', sizeof(cpk_ctx_t));
    c.bn_aux_1 = BN_new();
    c.bn_aux_2 = BN_new();
    c.q = BN_new();
    c.mod = BN_new();
    c.ctx = BN_CTX_new();
    if (!c.bn_aux_1 || !c.bn_aux_2 || !c.q || !c.ctx)
    {
	clear_ctx(&c);
	return print_fatal("cpk");
    }
    c.p = mcd(ne[0], n2);
    if (!ctx.p)
    {
	clear_ctx(&c);
	return NULL;
    }
    c.q = q(ne[0], &c);
    c.d = d(&c);
#ifdef DEBUG
    printf("\n~~ ** cpk operations ** ~~\n");
    printf("~~           p          ~~\n");
    BN_print_fp(stdout, c.p);
    printf("~~           q          ~~\n");
    BN_print_fp(stdout, c.q);
    printf("\n~~ **      end        ** ~~\n");
#endif
    return NULL;
}
