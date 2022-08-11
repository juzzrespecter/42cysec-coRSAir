#include "corsair.h"

static int print_usage(void)
{
    static const char usage[] = "usage: ./coRSAir CERT1 CERT2\n";

    write(STDERR_FILENO, usage, sizeof(usage));
    return EXIT_FAILURE;
}

int main(int argc, char *argv[])
{
    cert_ctx_t* c[2] = {0};
    
    if (argc != 3)
	    return print_usage();
    /* Parse ingoing certs. and extract (n,e) for each one */
    for (int i = 0; i < 2; i++)
    {
        c[i] = malloc(sizeof(cert_ctx_t));
        if (!parse_certificate(argv[i+1], c[i]))
            wrap_exit(c, EXIT_FAILURE);
    }
    /* generate private key for 1st. cert */
    gpk(c[0]->ne, c[1]->ne[0]);
    wrap_exit(c, EXIT_SUCCESS);
}
