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

enum
{
    SUCCESS,
    FAILURE
} status_e;

typedef struct cert_ctx_s
{
    int       fd;
    BIO*      bio_x;
    BIO*      bio_pubk;
    EVP_PKEY* pkey;
    X509*     x;
    RSA*      rsa;
    BIGNUM*   ne[2];
} cert_ctx_t;

typedef struct mcd_ctx_s
{
    BIGNUM *r;
    BN_CTX *ctx;
} mcd_ctx_t;

typedef struct gpk_ctx_s
{
    BIGNUM* bn_aux_1;
    BIGNUM* bn_aux_2;
    BIGNUM* p;
    BIGNUM* q;
    BIGNUM* d;
    BIGNUM* p_sub;
    BIGNUM* q_sub;
    BIGNUM* one;
    BIGNUM* mod;
    BIGNUM* dP;
    BIGNUM* dQ;
    BIGNUM* qInv;
    BN_CTX* ctx;
    RSA*    rsa;
} gpk_ctx_t;

typedef struct wtd_ctx_s
{
    int  fd;
    BIO* b;
} wtd_ctx_t;

cert_ctx_t* parse_certificate(char*, cert_ctx_t*);
BIGNUM*     mcd(const BIGNUM*, const BIGNUM*);
int         gpk(BIGNUM**, const BIGNUM*);
int         write_to_disk(RSA*);

/* ~~ utils ~~~ */
void  clean(cert_ctx_t*);
void* print_fatal(const char*);
void* syscall_error(const char*);
void  wrap_exit(cert_ctx_t**, int);

# define GR "\033[32m"
# define YL "\033[33m"
# define RD "\033[31m"
# define FN "\033[0m"

# endif // __CORSAIR_H__
