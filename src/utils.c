#include "corsair.h"

void clean(cert_struct_t* c)
{
    if (c->fd > 0)
	close(c->fd);
    if (c->bio)
	BIO_free(c->bio);
    if (c->rsa)
	RSA_free(c->rsa);
}

void wrap_exit(cert_struct_t* c, int EXIT_STATUS)
{
    clean(c);
    exit(EXIT_STATUS);
}
