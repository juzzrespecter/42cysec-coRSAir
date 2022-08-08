#ifndef __CORSAIR_H__
# define __CORSAIR_H__
# include <math.h>
# include <string.h>
# include <openssl/evp.h>
# include <openssl/ssl.h>
# include <openssl/rsa.h>
# include <openssl/pem.h>
# include <openssl/x509.h>
# include <openssl/asn1.h>
# include <openssl/err.h>
# include <fcntl.h>
# include <unistd.h>
# include <errno.h>

/* delete this !! */
# include <assert.h>

# define CERT_BUFFER_SIZE 4000
# define PUBKEY_ALGO_LEN 500

typedef struct pem_cert_s
{
    int       fd;
    BIO*      bio;
    X509*     x509;
    EVP_PKEY* pkey;
} pem_cert_t;

void wrap_exit(pem_cert_t *c, int EXIT_STATUS);
int wrap_open(char *fn, pem_cert_t *c);
int wrap_read(int fildes, char* buf, int nbyte, pem_cert_t *c);
BIO* wrap_BIO_new(const BIO_METHOD *type, pem_cert_t *c);
void wrap_BIO_write(BIO *b, const void *data, int dlen, pem_cert_t *c);
X509* wrap_PEM_read_bio_X509(BIO *bp, pem_cert_t *c);
EVP_PKEY* wrap_X509_get_pubkey(X509 *x, pem_cert_t *c);

# endif // __CORSAIR_H__
