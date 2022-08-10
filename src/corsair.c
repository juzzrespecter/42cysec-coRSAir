#include "corsair.h"

void print_usage(void)
{
    static const char usage[] = "usage: ./coRSAir CERT1 CERT2\n";

    write(STDERR_FILENO, usage, sizeof(usage));
}

int main(int argc, char *argv[])
{
    cert_ctx_t *c[2];
    
    if (argc != 3)
    {
	    print_usage();
	    return EXIT_FAILURE;
    }
    /* Parse ingoing certs. and extract (n,e) for each one */
    for (int i = 0; i < 2; i++)
    {
        c[i] = malloc(sizeof(cert_ctx_t));
        memset(c[i], '\0', sizeof(cert_ctx_t));
        c[i] = parse_certificate(argv[i+1], c[i]);
        if (!c[i])
            wrap_exit(c, EXIT_FAILURE);
    }
    /* generate private key for 1st. cert */
    if (cpk(c[0]->ne, c[1]->ne[0]); /* we need n, e, p !! */
    printf("** [dev] END OF CORSAIR **\n");
}


/*     TRAZOS PARA LA FUNC. CREAR PRIVATE KEY      */
/*-------------------------------------------------*/
/*     RSA_generate_key(int nm, unsigned long e,   */
/*               void (*cb)(int,int,void*),        */
/*               void *cb_arg)                     */
/*     RSA_check_key()                             */
