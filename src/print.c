#include "../inc/nmap.h"

void	print_usage( void )
{
	printf("ft_nmap 1.0\n Usage: ./ft_nmap [--scan VALUE1 VALUE2 ... ] [--speedup N] [--ports X/Y] --ip hostname|ip_addr.\n\n");
	printf("--scan VAL\t: VAL can be one of these values: SYN, NULL, ACK, FIN, XMAS, UDP.\n\t\t  One or multiple values can be specified.\n");
	printf("--speedup N\t: N must be a positive number less than 250 included.\n");
	printf("--ports X/Y\t: X and Y define a range of ports to scan. Y is not required.\n\t\t  Both X and Y must positive number. The range defined has to be less than 1024 long.\n");
	printf("--file filename\t: filename is a file containing multiple hostnames used as input.\n");
	printf("--no-ping\t: disable the ping request before the actual scan.\n");
	printf("--rand-target\t: send requests to random hosts.\n");
	printf("--max-tries N\t: Caps number of port scan probe retransmissions.\n");
	printf("--ttl N\t\t: Set IP time-to-live field.\n");
	printf("--interface string\t : Use specified interface.\n");
	printf("--ip ip_addr or hostname : is required. ip_addr a IPv4 IP address and hostname is a hostname.\n\t\t\t   Only a single ip address or hostname is required.\n");
}

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

char *return_str_state(int state)
{
	switch (state)
	{
	case OPEN:
		return "open";
		break;
	case CLOSE:
		return "close";
		break;
	case FILTERED:
		return "filtered";
		break;
	case OPEN_FILT:
		return "open/filtered";
		break;
	case CLOSE_FILT:
		return "close/filtered";
		break;
	case UNFILTERED:
		return "unfiltered";
		break;
	default:
		return "unknow";
		break;
	}
	return "unknow";
}

char *return_str_type(int type)
{
	switch (type)
	{
	case SYN:
		return "SYN";
		break;
	case S_NULL:
		return "NULL";
		break;
	case FIN:
		return "FIN";
		break;
	case XMAS:
		return "XMAS";
		break;
	case ACK:
		return "ACK";
		break;
	case UDP:
		return "UDP";
		break;
	default:
		return "SYN NULL FIN XMAS ACK UDP";
		break;
	}
}

void print_space(uint8_t space)
{
	for (; space > 0; space --)
		printf(" ");
}

void print_port(t_scan_port *port, t_info *info)
{
	uint8_t space_nbr = 6 - ft_nblen(port->nb);
	printf("%d/", port->nb);
	if (info->scan_type[0] >= SYN && info->scan_type[0] <= XMAS)
		printf("tcp");
	else
		printf("udp");
	print_space(space_nbr);
}

void print_line(t_scan_port *port, t_info *info)
{
	int state = 0;
	int first_print = true;
	int scan_type = 0;

	for (int i = 0; i < NB_MAX_SCAN; i++)
	{
		scan_type = info->scan_type[i];
		state = port->state[scan_type];
		if (scan_type == -1)
			continue;
		if (state != OPEN && info->port_range > 10)
			continue;
		char *str_state = return_str_state(state);
		char *str_type = return_str_type(scan_type);
		uint8_t space_state = 19 - strlen(str_state) - 2 - strlen(str_type);
		if (first_print)
		{
			print_port(port, info);
			printf("%s(%s)", str_state, str_type);
			print_space(space_state);
			if (scan_type >= SYN && scan_type <= XMAS)
				printf("%s\n", return_service_tcp(port->nb));
			else
				printf("%s\n", return_service_udp(port->nb));
			first_print = false;
		}
		else
			printf("          %s(%s)\n", str_state, str_type);
	}
}

void	super_print( t_host *host, t_info *info )
{
	printf("\n");

	printf("Scan Configurations:\n");
	printf("Nbr of Ports to scan: %d\n", info->port_range);
	printf("Nbr of threads: %d\n", info->nb_thread);
	printf("Scans to be performed: ");
	char *scan;
	for (int scan_type = 0; scan_type < NB_MAX_SCAN; scan_type++)
	{
		if (info->scan_type[scan_type] != -1)
		{
			scan = return_str_type(info->scan_type[scan_type]);
			printf("%s ", scan);
		}
	}
	printf("\n\n");

	while (host != NULL)
	{
		printf("HOST: %s\n", host->name);
		printf("Host is up\n");
		int not_open = info->port_range - host->open;
		if (not_open != 0 && info->port_range > 10)
			printf("Not shown: %d ports\n", not_open);
		if (not_open != info->port_range || info->port_range <= 10)
			printf("PORT      STATE              SERVICE\n");
		for (uint16_t i = 0; i < info->port_range; i++)
			print_line(&host->port_tab[i], info);
		host = host->next;
		printf("\n");
	}
	double second = time_till_start(&info->time_start);
	printf("Nmap done: %d IP address (%d host up) scanned in %0.2f seconds\n", 
				info->nb_host_ping, info->nb_host_ping_success, second);
}