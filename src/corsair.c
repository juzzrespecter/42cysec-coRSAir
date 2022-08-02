#include "corsair.h"

void print_usage(void)
{
    const static char usage[] = "usage: ./coRSAir CERT1 CERT2 MSG\n";

    write(STDERR_FILENO, usage, sizeof(usage));
}

/* Parameters: cert1, cert2, msg ?? */
int main(int argc, char *argv[])
{
    if (argc != 3)
    {
	print_usage();
	return EXIT_FAILURE;
    }
    /* ... */
}
