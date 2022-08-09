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

typedef struct cert_ctx_s
{
    int       fd;
    BIO*      bio_x;
    BIO*      bio_pubk;
    EVP_PKEY* pkey;
    X509*     x;
    RSA*      rsa;
    const BIGNUM* ne[2];
} cert_ctx_t;

typedef struct mcd_ctx_s
{
    BIGNUM *r;
    BN_CTX *ctx;
} mcd_ctx_t;

typedef struct cpk_ctx_s
{
    BIGNUM* dv;
    BIGNUM* rem;
    BN_CTX* ctx;
} cpk_ctx_t;

cert_ctx_t* parse_certificate(char*, cert_ctx_t*);
BIGNUM*     mcd(const BIGNUM*, const BIGNUM*);
void* /*TMP*/cpk(const BIGNUM*, const BIGNUM*);

/* ~~ utils ~~~ */
void clean(cert_ctx_t*);
void* print_fatal(const char*);
void wrap_exit(cert_ctx_t**, int);

# endif // __CORSAIR_H__
