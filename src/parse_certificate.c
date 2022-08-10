#include "corsair.h"

static X509 *parse_x509(cert_ctx_t *c)
{
    char    c_buf[C_BUF_LEN] = {0};
    ssize_t r;

    r = read(c->fd, c_buf, C_BUF_LEN - 1);
    if (r < 0)
	return syscall_error("read");
    c->bio_x = BIO_new(BIO_s_mem());
    if (!c->bio_x)
        return print_fatal("BIO_new");
    if (BIO_write(c->bio_x, c_buf, strlen(c_buf)) < 0)
        return print_fatal("BIO_write");
    c->x = PEM_read_bio_X509(c->bio_x, NULL, NULL, NULL);
    if (!c->x)
        return print_fatal("PEM_read_bio_X509");
#ifdef DEBUG
    printf(GR"~~ X509 cert. ~~\n"FN);
    X509_print_fp(stdout, c->x);
#endif
    return c->x;
}

static RSA *extract_RSA_pubk(cert_ctx_t *c)
{
    c->bio_pubk = BIO_new(BIO_s_mem());
    if (!c->bio_pubk)
        return print_fatal("BIO_new");
    c->pkey = X509_get_pubkey(c->x);
    if (!c->pkey)
        return print_fatal("X509_get_pubkey");
    if (PEM_write_bio_PUBKEY(c->bio_pubk, c->pkey) < 0)
        return print_fatal("PEM_write_bio_PUBKEY");
    c->rsa = RSA_new();
    c->rsa = PEM_read_bio_RSA_PUBKEY(c->bio_pubk, &c->rsa, NULL, NULL);
    if (!c->rsa)
    {
        printf("fatal: no RSA pub. key present in one of provided certs. exiting...\n");
        return NULL;
    }
#ifdef DEBUG
    printf(GR"~~ for x509 cert. extracted pub. key ~~\n"FN);
    RSA_print_fp(stdout, c->rsa, 0);
#endif
    return c->rsa;
}

static cert_ctx_t* get_e_n(cert_ctx_t *c)
{
    const BIGNUM* key[2] = {0};

    RSA_get0_key(c->rsa, &key[0], &key[1], NULL);
    for (int i = 0; i < 2; i++)
    {
        if (!key[i])
        {
            printf("fatal: could not get public key values from RSA key.\n");
            return NULL;
        }
        c->ne[i] = BN_dup(key[i]);
    }
    return c;
}

cert_ctx_t *parse_certificate(char *cert_fn, cert_ctx_t *c)
{
    if (c == NULL)
	return syscall_error("malloc");
    memset(c, '\0', sizeof(cert_ctx_t));
    c->fd = open(cert_fn, O_RDONLY);
    if (c->fd < 0)
	return syscall_error("open");
    c->x = parse_x509(c);
    if (!c->x)
        return NULL;
    c->rsa = extract_RSA_pubk(c);
    if (!c->rsa)
        return NULL;
    if (!get_e_n(c))
        return NULL;
    return c;
}
