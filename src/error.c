#include "../inc/nmap.h"

void fatal_error(char *err)
{
    fprintf(stderr, "%s\n", err);
    exit(1);
}

void fatal_perror(char *err)
{
    perror(err);
    exit(2);
}

void fatal_error_str(char *message, char *err)
{
    fprintf(stderr, message, err);
    exit(3);
}