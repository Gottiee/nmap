#include "../inc/nmap.h"

// 65532 max port
 
int    ft_nblen(int nb)
{
    int        len;
    long    n;

    len = 0;
    n = nb;
    if (n == 0)
        return (1);
    while (n > 0)
    {
        len++;
        n /= 10;
    }
    return (len);
}

void print_port(t_scan_port *port, t_info *info)
{
	// gerer apres si c'est scan all
	uint8_t space_nbr = 6 - ft_nblen(port->nb);

	printf("%d/", port->nb);
	if (info->scan_type >= SYN && info->scan_type <= XMAS)
		printf("tcp");
	else
		printf("udp");
	for (; space_nbr > 0; space_nbr --)
		printf(" ");
	printf("\n");

	// printf("\tport %d |",port_tab->nb);
	// printf(" state %d\n", port_tab->state[info->scan_type]); //	FAUX SI SCAN ALL
}

void	super_print( t_host *host, t_info *info )
{
	printf("\n");

	printf("Scan Configurations:\n");
	printf("Nbr of Ports to scan: %d\n", info->port_range);
	printf("Scans to be performed: ");
	switch (info->scan_type)
	{
	case SYN:
		printf("SYN\n\n");
		break;
	case S_NULL:
		printf("NULL\n\n");
		break;
	case FIN:
		printf("FIN\n\n");
		break;
	case XMAS:
		printf("XMAS\n\n");
		break;
	case ACK:
		printf("ACK\n\n");
		break;
	case UDP:
		printf("UDP\n\n");
		break;
	default:
		printf("SYN NULL FIN XMAS ACK UDP\n\n");
		break;
	}

	while (host != NULL)
	{
		printf("HOST: %s\n", host->name);
		printf("Host is up\n");
		// ici calculer le nombre de filtered / close ...
		// int not_open = info->port_range - host->open;
		// printf("Not shown: %d filtered tcp ports (no-response)", not_open);
		printf("Not shown: ? filtered tcp ports (no-response)\n");
		printf("PORT      STATE         SERVICE\n");
		for (uint16_t i = 0; i < info->port_range; i++)
			print_port(&host->port_tab[i], info);
		host = host->next;
	}
	double second = time_till_start(&info->time_start);
	printf("Nmap done: %d IP address (%d host up) scanned in %0.2f seconds\n", 
				info->nb_host_ping, info->nb_host_ping_success, second);
}