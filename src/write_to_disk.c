#include "corsair.h"

const char* pkey_fn = "cracked_pkey.pem";

static void clear_ctx(wtd_ctx_t* c)
{
    if (c->fd > 0)
	close(c->fd);
    if (c->b)
	BIO_free_all(c->b);
}

int write_to_disk(RSA* pkey)
{
    wtd_ctx_t c;
    char      pkey_buf[C_BUF_LEN] = {0};

    memset(&c, '\0', sizeof(wtd_ctx_t));
    c.fd = open(pkey_fn, O_WRONLY|O_TRUNC|O_CREAT, 0600);
    if (c.fd < 0)
    {
	printf("open: %s\n", strerror(errno));
	clear_ctx(&c);
	return FAILURE;
    }
    c.b = BIO_new(BIO_s_mem());
    if (!c.b)
    {
	print_fatal("BIO_new");
	clear_ctx(&c);
	return FAILURE;
    }
    if (RSA_print(c.b, pkey, 0))
    {
	print_fatal("RSA_print");
	clear_ctx(&c);
	return FAILURE;
    }
    if (BIO_write(c.b, pkey_buf, strlen(pkey_buf)))
    {
	print_fatal("BIO_write");
	clear_ctx(&c);
	return FAILURE;
    }
    write(c.fd, pkey_buf, strlen(pkey_buf));
#ifdef DEBUG
    //RSA_check_key(pkey);
#endif
    clear_ctx(&c);
    return SUCCESS;
}
