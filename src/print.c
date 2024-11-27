#include "../inc/nmap.h"

void	super_print( t_host *host, t_info *info )
{
	printf("\n");
	while (host != NULL)
	{
		printf("HOST: %s\n", host->name);
		for (uint16_t i = 0; i < info->port_range; i++)
		{
			printf("\tport %d |", host->port_tab[i].nb);
			printf(" state %d\n", host->port_tab[i].state);
		}
		host = host->next;
	}
	double second = time_till_start(&info->time_start);
	printf("Nmap done: %d IP address (%d host up) scanned in %0.2f seconds\n", 
				info->nb_host_ping, info->nb_host_ping_success, second);
}