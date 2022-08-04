#ifndef __CORSAIR_H__
# define __CORSAIR_H__
# include <math.h>
# include <string.h>
# include <openssl/evp.h>
# include <openssl/ssl.h>
# include <openssl/rsa.h>
# include <openssl/x509.h>
# include <fcntl.h>

typedef struct
{
    unsigned long m;
    unsigned int e;
} public_key_t

public_key_t *parse_cert(char *);

# endif // __CORSAIR_H__
