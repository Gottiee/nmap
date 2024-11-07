#include "../inc/nmap.h"

double time_till_start(struct timeval *start)
{
	struct timeval end;

    gettimeofday(&end, NULL);
    return (end.tv_sec - start->tv_sec) + (end.tv_usec - start->tv_usec) / 1e6;
}

t_host *add_host_list(char *name, t_host *start)
{
    t_host *new = malloc(sizeof(t_host));
    if (!new)
        fatal_perror("Malloc error \"t_host *new\"");

    while (start->next)
    {
        start->next = new;
        new->next = NULL;
        new->name = name;
    }
    return new;
}

t_host *init_host_list(char *name)
{
    t_host *start = malloc(sizeof(t_host));
    if (!start)
        fatal_perror("Error malloc \"t_host start\"");
    start->next = NULL;
    start->name = name;
    return start;
}

void free_host_list(t_host *start)
{
    t_host *tmp = NULL;
    while (start)
    {
        tmp = start;
        start = start->next;
        free(tmp);
    }
}