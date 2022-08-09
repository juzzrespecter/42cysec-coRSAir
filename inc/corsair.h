#ifndef __CORSAIR_H__
# define __CORSAIR_H__
# include <math.h>
# include <string.h>
# include <openssl/evp.h>
# include <openssl/rsa.h>
# include <openssl/pem.h>
# include <openssl/err.h>
# include <fcntl.h>
# include <unistd.h>
# include <errno.h>

# define C_BUF_LEN 4000

typedef struct cert_ref_s
{
    int       fd;
    BIO*      bio_x;
    BIO*      bio_pubk;
    EVP_PKEY* pkey;
    X509*     x;
    RSA*      rsa;
} cert_ref_t;

typedef struct pkey_pair_s
{
    BIGNUM* n;
    BIGNUM* e;
} pkey_pair_t;

cert_ref_t* parse_certificate(char*, cert_ref_t*);
void clean(cert_ref_t *);
void wrap_exit(cert_ref_t *, int);

# endif // __CORSAIR_H__
