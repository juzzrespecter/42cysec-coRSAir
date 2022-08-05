#include "corsair.h"

void print_usage(void)
{
    const static char usage[] = "usage: ./coRSAir CERT1 CERT2\n";

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

    int test_fd = open(argv[1], O_RDONLY);
    if (test_fd == -1)
    {
        printf("open: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
}
