#include "corsair.h"

void print_usage(void)
{
   static const char usage[] = "usage: ./coRSAir CERT1 CERT2\n";

    write(STDERR_FILENO, usage, sizeof(usage));
}

/* OBJ_obj2nid(): returns Numeric ID from object              */
/* OBJ_nid2ln(): returns long name from Numeric ID            */

/* ENV_PKEY_type(): returns underlying type of NID type       */
/* ENV_PKEY_get1_RSA(): returns the referenced key in pkey    */

void parse_cert(char* cert_fn)
{
    pem_cert_t cert;
    char       cert_buffer[CERT_BUFFER_SIZE] = {0};

    memset(&cert, '\0', sizeof(cert));
    cert.fd = wrap_open(cert_fn, &cert);
    wrap_read(cert.fd, cert_buffer, CERT_BUFFER_SIZE - 1, &cert);      /* Read cert.pem to memory */
    cert.bio = wrap_BIO_new(BIO_s_mem(), &cert);                       /* Create new BIO          */
    wrap_BIO_write(cert.bio, cert_buffer, strlen(cert_buffer), &cert); /* Write cert in memory to BIO */
    cert.x509 = wrap_PEM_read_bio_X509(cert.bio,&cert); /* Parse BIO to X509 cert. structure */
    cert.pkey = wrap_X509_get_pubkey(cert.x509, &cert);                         /* Extract public key from cert. */
    if (EVP_PKEY_type(EVP_PKEY_get_base_id(cert.pkey)) != NID_rsaEncryption)
    {
        printf("Cert. not RSA encryption");
        wrap_exit(&cert, EXIT_FAILURE);
    }

}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
	    print_usage();
	    return EXIT_FAILURE;
    }
    parse_cert(argv[1]);
}


/*     TRAZOS PARA LA FUNC. CREAR PRIVATE KEY      */
/*-------------------------------------------------*/
/*     RSA_generate_key(int nm, unsigned long e,   */
/*               void (*cb)(int,int,void*),        */
/*               void *cb_arg)                     */
/*     RSA_check_key()                             */
