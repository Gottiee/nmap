#include "../inc/nmap.h"

void fatal_error(char *err)
{
    fprintf(stderr, err);
    exit(1);
}

void fatal_perror(char *err)
{
    perror(err);
    exit(2);
}