#include "corsair.h"

const char *pkey_fn = "cracked_pkey.pem";

static int clear_ctx(wtd_ctx_t *c, int EXIT_STATUS)
{
    if (c->fd > 0)
        close(c->fd);
    if (c->b)
        BIO_free_all(c->b);
    return EXIT_STATUS;
}

int write_to_disk(RSA *pkey)
{
    wtd_ctx_t c;
    char pkey_buf[C_BUF_LEN] = {0};

    memset(&c, '\0', sizeof(wtd_ctx_t));
    c.fd = open(pkey_fn, O_WRONLY | O_TRUNC | O_CREAT, 0600);
    if (c.fd < 0)
    {
        syscall_error("open");
        return clear_ctx(&c, FAILURE);
    }
    c.b = BIO_new(BIO_s_mem());
    if (!c.b)
    {
        print_fatal("BIO_new");
        return clear_ctx(&c, FAILURE);
    }
    if (!PEM_write_bio_RSAPrivateKey(c.b, pkey, NULL, NULL, 0, NULL, NULL))
    {
        print_fatal("PEM_write_bio_RSAPrivateKey");
        return clear_ctx(&c, FAILURE);
    }
    if (BIO_read(c.b, pkey_buf, C_BUF_LEN - 1) < 0)
    {
        print_fatal("BIO_write");
        return clear_ctx(&c, FAILURE);
    }
    write(c.fd, pkey_buf, strlen(pkey_buf));
#ifdef DEBUG
    printf("testing...\n");
    // RSA_check_key(pkey);
#endif
    printf(GR "~~ created %s ~~\n" FN, pkey_fn);
    return clear_ctx(&c, SUCCESS);
}
