#include "corsair.h"

const char *pkey_fn = "cracked_pkey.pem";

static int clear_ctx(wtd_ctx_t *c, int EXIT_STATUS)
{
    if (c->b)
        BIO_free_all(c->b);
    return EXIT_STATUS;
}

int write_to_disk(RSA *pkey)
{
    wtd_ctx_t c;

    memset(&c, '\0', sizeof(wtd_ctx_t));
    c.b = BIO_new_file(pkey_fn, "w");
    if (!c.b)
    {
        print_fatal("BIO_new");
        return clear_ctx(&c, FAILURE);
    }
    if (!PEM_write_bio_RSAPrivateKey(c.b, pkey, NULL, NULL, 0, NULL, NULL))
    {
        print_fatal("PEM_write_bio_RSAPrivateKey");
        return clear_ctx(&c, FAILURE);
    }
#ifdef DEBUG
    printf(GR"~~ RSA key cert. ~~\n"FN);
    RSA_print_fp(stdout, pkey, 0);
    printf("\n~~               ~~\n"FN);
#endif
    printf(GR"~~ 🔑✨ created %s 🔑✨ ~~\n"FN, pkey_fn);
    return clear_ctx(&c, SUCCESS);
}
