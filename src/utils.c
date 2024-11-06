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
    start->next = NULL;
    start->name = name;
    return start;
}