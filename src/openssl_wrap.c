#include "corsair.h"

/* BIO_free(): frees up a BIO struct                                  */
/* X509_free(): decrements ref. && frees up a X509 struct if ref == 0 */
/* EVP_PKEY_free(): decrements & frees EVP_PKEY if needed             */

void wrap_exit(pem_cert_t *c, int EXIT_STATUS)
{
    if (c->fd > 0)
        close(c->fd);
    if (c->bio)
        BIO_free(c->bio);
    if (c->x509)
        X509_free(c->x509);
    if (c->pkey)
        EVP_PKEY_free(c->pkey);
    exit(EXIT_STATUS);
}

int wrap_open(char *fn, pem_cert_t *c)
{
    int fd = open(fn, O_RDONLY);

    if (fd == -1)
    {
        printf("open: %s", strerror(errno));
        wrap_exit(c, EXIT_FAILURE);
    }
    return fd;
}

int wrap_read(int fildes, char* buf, int nbyte, pem_cert_t *c)
{
    int ret = read(fildes, buf, nbyte);

    if (ret < 0)
    {
        printf("read: %s", strerror(errno));
        wrap_exit(c, EXIT_FAILURE);
    }
    return ret;
}

BIO* wrap_BIO_new(const BIO_METHOD *type, pem_cert_t *c)
 {
     BIO* bio = BIO_new(type);

    if (bio == NULL)
    {
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        wrap_exit(c, EXIT_FAILURE);
    }
    return bio; 
 }

void wrap_BIO_write(BIO *b, const void *data, int dlen, pem_cert_t *c)
{
    int ret = BIO_write(b, data, dlen);
    
    if (ret < 0)
    {
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        wrap_exit(c, EXIT_FAILURE);
    }
}

/* PEM_read_bio_X509(): read a cert. in PEM format from a BIO */

X509* wrap_PEM_read_bio_X509(BIO *bp, pem_cert_t *c)
{
    X509* x509 = PEM_read_bio_X509(bp, NULL, NULL, NULL);

    if (x509 == NULL)
    {
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        wrap_exit(c, EXIT_FAILURE);
    }
    return x509;
}

EVP_PKEY* wrap_X509_get_pubkey(X509 *x, pem_cert_t *c)
{
    EVP_PKEY* pkey = X509_get_pubkey(x);
    if (pkey == NULL)
    {
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        wrap_exit(c, EXIT_FAILURE);
    }
    return pkey;
}