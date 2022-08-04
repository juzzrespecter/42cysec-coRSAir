#include "corsair.h"

void print_usage(void)
{
    const static char usage[] = "usage: ./coRSAir CERT1 CERT2 MSG\n";

    write(STDERR_FILENO, usage, sizeof(usage));
}

/* Parameters: cert1, cert2, msg ?? */
int main(int argc, char *argv[])
{
    public_key_t *public_key_arr[2];

    if (argc != 3)
    {
	    print_usage();
	    return EXIT_FAILURE;
    }
    for (int i = 0; i < 2; i++)
    {
        public_key_arr[i] = parse_cert(argv[i + 1]);
        if (public_key_arr[i] == NULL)
        {
            fatal(public_key_arr);
        }
    }
    /* Calcula maximo comun divisor entre las dos PK */
    /* if res == 1
            no vuln, ret;
        else
            p == res
            q == PK / res

            d = func(p,q)
            decript_msg(msg,n,d)
        

}
