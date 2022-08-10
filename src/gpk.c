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
	BN_free(c->dP);	
    if(c->dQ)
	BN_free(c->dQ);	
    if(c->qInv)
	BN_free(c->qInv);	
    if(c->ctx)
	BN_CTX_free(c->ctx);	
}

/* obtain second prime number from shared prime & 1st cert. modulus */
static BIGNUM* q(const BIGNUM* n, gpk_ctx_t* c)
{
    if (!BN_div(c->q, c->bn_aux_1, n, c->p, c->ctx))
        return print_fatal("BN_div");
    if (!BN_is_zero(c->bn_aux_1))
    {
        printf("fatal: could not get second prime number\n");
        return NULL;
    }
    return c->q;
}

/* generate decrypt exp. for private key */
static BIGNUM* d(BIGNUM* e, gpk_ctx_t* c)
{
    if (!BN_dec2bn(&c->one, "1"))
	return NULL;
    if (!BN_sub(c->p_sub, c->p, c->one))
	return NULL;
    if (!BN_sub(c->q_sub, c->q, c->one))
	return NULL;
    if (!BN_mul(c->mod, c->p_sub, c->q_sub, c->ctx))
	return NULL;
    return BN_mod_inverse(NULL, e, c->mod, c->ctx);
}

/* generate CRT exponents & coeff. for private key */
static gpk_ctx_t* build_params(const BIGNUM* e, gpk_ctx_t* c)
{
    c->dP = BN_mod_inverse(NULL, e, c->p_sub, c->ctx);
    c->dQ = BN_mod_inverse(NULL, e, c->q_sub, c->ctx);
    c->qInv = BN_mod_inverse(NULL, c->q, c->p, c->ctx);
    if (!c->dP || !c->dQ || !c->qInv)
	return print_fatal("BN_mod_inverse");
    return c;
}

/* generate RSA key structure */
static RSA* gen_priv_key(BIGNUM* ne[2], gpk_ctx_t* c)
{
    c->rsa = RSA_new();

    if (!c->rsa)
	return print_fatal("RSA_new");
    RSA_set0_key(c->rsa, ne[0], ne[1], c->d);
    RSA_set0_factors(c->rsa, c->p, c->q);
    RSA_set0_crt_params(c->rsa, c->dP, c->dQ, c->qInv);
    return c->rsa;
}

int gpk(BIGNUM* ne[2], const BIGNUM* n2)
{
    gpk_ctx_t c;
    
    memset(&c, '\0', sizeof(gpk_ctx_t));
    c.bn_aux_1 = BN_new();
    c.bn_aux_2 = BN_new();
    c.q = BN_new();
    c.mod = BN_new();
    c.ctx = BN_CTX_new();
    if (!c.bn_aux_1 || !c.bn_aux_2 || !c.q || !c.mod || !c.ctx)
    {
	clear_ctx(&c);
	return FAILURE;
    }
    c.p = mcd(ne[0], n2);
    if (!c.p)
    {
	clear_ctx(&c);
	return FAILURE;
    }
    c.q = q(ne[0], &c);
    if (!c.q)
    {
	clear_ctx(&c);
	return FAILURE;
    }
    c.d = d(ne[1], &c);
    
#ifdef DEBUG
    printf("\n~~ ** cpk operations ** ~~\n");
    printf("~~           p          ~~\n");
    BN_print_fp(stdout, c.p);
    printf("~~           q          ~~\n");
    BN_print_fp(stdout, c.q);
    printf("~~           d          ~~\n");
    BN_print_fp(stdout, c.d);
    printf("\n~~ **      end        ** ~~\n");
#endif

    if (!build_params(ne[1], &c))
    {
	clear_ctx(&c);
	return FAILURE;
    }
    gen_priv_key(ne, &c);
    clear_ctx(&c);
    return SUCCESS;
}
