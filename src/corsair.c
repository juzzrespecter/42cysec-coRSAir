#include "corsair.h"

void print_usage(void)
{
   static const char usage[] = "usage: ./coRSAir CERT1 CERT2\n";

    write(STDERR_FILENO, usage, sizeof(usage));
}

/* PEM_read_bio_X509(): read a cert. in PEM format from a BIO */
/* OBJ_obj2nid(): returns Numeric ID from object              */
/* OBJ_nid2ln(): returns long name from Numeric ID            */

/* Parameters: cert1, cert2, msg ?? */
int main(int argc, char *argv[])
{
    char cert_buffer[BUFFER_SIZE];
    
    if (argc != 3)
    {
	    print_usage();
	    return EXIT_FAILURE;
    }

    int test_fd = open(argv[1], O_RDONLY);
    if (test_fd == -1)
    {
        printf("open: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    memset((void *)cert_buffer, '\0', BUFFER_SIZE);
    ssize_t read_fd = read(test_fd, cert_buffer, BUFFER_SIZE);
    if (read_fd == -1)
    {
	printf("read: %s\n", strerror(errno));
	return EXIT_FAILURE;
    }
    BIO *certBIO = BIO_new(BIO_s_mem());
    BIO_write(certBIO, cert_buffer, strlen(cert_buffer));
    X509* certX509 = PEM_read_bio_X509(certBIO, NULL, NULL, NULL);
    if (certX509 == NULL)
    {
	printf("PEM_read_bio_X509: %s\n", strerror(errno));
	return EXIT_FAILURE;
    }
    printf("pilla certificados validos\n");

    EVP_PKEY *pkey = X509_get_pubkey(certX509);
    if (pkey == NULL)
    {
	printf("X509_get_pubkey: could not extract public key from cert.\n");
	return EXIT_FAILURE;
    }
    printf("pilla public key del certificado\n");
    int algo_id = OBJ_obj2nid(certX509->cert_info->key->algor->algorithm);
    if (algo_id == NID_undef)
    {
	printf("OBJ_obj2nid: could not find specified public key algo. name\n");
	return EXIT_FAILURE;
    }
    
}
