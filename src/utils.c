#include "../inc/nmap.h"

bool	return_error( char *err_mess )
{
	perror(err_mess);
	return (1);
}

double time_till_start(struct timeval *start)
{
	struct timeval end;

    gettimeofday(&end, NULL);
    return (end.tv_sec - start->tv_sec) + (end.tv_usec - start->tv_usec) / 1e6;
}

t_host *add_host_list(char *name, t_host *start, t_info *info)
{
    t_host *new = malloc(sizeof(t_host));
    if (!new)
        fatal_perror("Malloc error \"t_host *new\"");

    while (start->next)
    {
        start->next = new;
        new->next = NULL;
        new->name = name;
		start->port_tab = malloc(sizeof(t_scan_port) * (info->port_range));
		if (start->port_tab == NULL)
			fatal_perror("Malloc error \"t_host *new\"");
    }
    return new;
}

t_host *init_host_list(char *name, t_info *info)
{
    t_host *start = malloc(sizeof(t_host));
    if (!start)
        fatal_perror("Error malloc \"t_host start\"");
    start->next = NULL;
    start->name = name;
	start->port_tab = calloc(info->port_range, sizeof(t_scan_port));
	if (start->port_tab == NULL)
			fatal_perror("Malloc error \"t_host *new\"");
    return start;
}

void free_host_list(t_host *start)
{
    t_host *tmp = NULL;
    while (start)
    {
        tmp = start;
		free(start->port_tab);
        start = start->next;
        free(tmp);
    }
}
