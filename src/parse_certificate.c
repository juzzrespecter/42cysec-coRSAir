#include "corsair.h"

static X509* parse_x509(cert_ref_t* c)
{
    char    c_buf[C_BUF_LEN] = {0};
    ssize_t r;

    r = read(c->fd, c_buf, C_BUF_LEN - 1);
    if (r < 0)
    {
	printf("read: %s\n", strerror(errno));
	return NULL;
    }
    c->bio_x = BIO_new(BIO_s_mem());
    if (!c->bio_x)
    {
	printf("fatal: [%s]\n", ERR_error_string(ERR_get_error(), NULL));
	return NULL;
    }
    if (BIO_write(c->bio_x, c_buf, strlen(c_buf)) < 0)
    {
	printf("fatal: [%s]\n", ERR_error_string(ERR_get_error(), NULL));
	return NULL;
    }
    c->x = PEM_read_bio_X509(c->bio_x, NULL, NULL, NULL);
    if (!c->x)
    {
	printf("fatal: [%s]\n", ERR_error_string(ERR_get_error(), NULL));
	return NULL;
    }
#ifdef DEBUG
    printf("~~ X509 cert. ~~\n");
    X509_print_fp(stdout, c->x, 0);
#endif
    return c->x;
}

static RSA* extract_RSA_pubk(cert_ref_t* c)
{
    c->bio_pubk = BIO_new(BIO_s_mem());
    if (!c->bio_pubk)
    {
	printf("fatal: [%s]\n", ERR_error_string(ERR_get_error(), NULL));
	return NULL;
    }
    c->pkey = X509_get_pubkey(c->x);
    if (!c->pkey)
    {
	printf("fatal: [%s]\n", ERR_error_string(ERR_get_error(), NULL));
	return NULL;
    }
    if (PEM_write_bio_PUBKEY(c->bio_pubk, c->pkey) < 0)
    {
	printf("fatal: [%s]\n", ERR_error_string(ERR_get_error(), NULL));
	return NULL;
    }
    c->rsa = PEM_read_bio_RSA_PUBKEY(c->bio_pubk, &c->rsa, NULL, NULL);
    if (!c->rsa)
    {
	printf("fatal: no RSA pub. key present in one of provided certs. exiting...\n");
	return NULL;
    }
#ifdef DEBUG
    printf("~~ for x509 cert. extracted pub. key ~~\n");
    RSA_print_fp(stdout, c->rsa, 0);
#endif
    return c->rsa;
}

cert_ref_t* parse_certificate(char* cert_fn, cert_ref_t* c)
{

    
    c->fd = open(cert_fn, O_RDONLY);
    if (c->fd < 0)
    {
	printf("open: %s\n", strerror(errno));
	return NULL;
    }
    
    c->x = parse_x509(c);
    if (!c->x)
    {
	return NULL;
    }
    c->rsa = extract_RSA_pubk(c);
    if (!c->rsa)
    {
	return NULL;
    }

    /* ~~ testing ~~ */
    const BIGNUM* key[3] = {0};

    RSA_get0_key(c->rsa, &key[0], &key[1], &key[2]);
    for (int i = 0; i < 3; i++)
    {
	if (key[i])
	{
	    printf("~~ key %d ~~\n", i);
	    BN_print_fp(stdout, key[i]);
	    printf("\n~~        ~~\n");
	}
    }
    
    /* ~~         ~~ */
    return c;
}
