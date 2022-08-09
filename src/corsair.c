#include "corsair.h"

void print_usage(void)
{
   static const char usage[] = "usage: ./coRSAir CERT1 CERT2\n";

    write(STDERR_FILENO, usage, sizeof(usage));
}

/* BIGNUM: */

/* RSA_new: allocate, init. an RSA struct.     */
/* BIO_new: returns new BIO with provided type */
/* BIO_s_file: returns BIO mem. method         */
/* BIO_write: writes from buf to BIO           */ 
/* BIO_read_bio_RSA_PUBKEY():                  */

int main(int argc, char *argv[])
{
    cert_ref_t *c;
    
    if (argc != 3)
    {
	    print_usage();
	    return EXIT_FAILURE;
    }
    c = malloc(sizeof(cert_ref_t));
    parse_certificate(argv[1], c);
}


/*     TRAZOS PARA LA FUNC. CREAR PRIVATE KEY      */
/*-------------------------------------------------*/
/*     RSA_generate_key(int nm, unsigned long e,   */
/*               void (*cb)(int,int,void*),        */
/*               void *cb_arg)                     */
/*     RSA_check_key()                             */
