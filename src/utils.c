#include "corsair.h"

void clean(cert_ctx_t *c)
{
    if (c->fd > 0)
        close(c->fd);
    if (c->bio_x)
        BIO_free_all(c->bio_x);
    if (c->bio_pubk)
        BIO_free_all(c->bio_pubk);
    if (c->pkey)
        EVP_PKEY_free(c->pkey);
    if (c->x)
        X509_free(c->x);
    if (c->rsa)
        RSA_free(c->rsa);
}

void *print_fatal(const char *ctx)
{
    printf("[%s] fatal: [%s]\n", ctx, ERR_error_string(ERR_get_error(), NULL));
    return NULL;
}

void wrap_exit(cert_ctx_t *c[2], int EXIT_STATUS)
{
    if (c[0])
    {
        clean(c[0]);
	free(c[0]);
    }
    if (c[1])
    {
        clean(c[1]);
	free(c[1]);
    }
    exit(EXIT_STATUS);
}
