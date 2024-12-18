#include "../inc/nmap.h"

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
	default:
		return "";
		break;
	}
	return "";
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
	if (info->scan_type >= SYN && info->scan_type <= XMAS)
		printf("tcp");
	else
		printf("udp");
	print_space(space_nbr);
}

void print_all(t_scan_port *port, t_info *info)
{
	int state = 0;

	for (int i = 0; i <= UDP; i++)
	{
		state = port->state[i];
		if (state != OPEN && state != OPEN_FILT)
			continue;
		char *str_state = return_str_state(state);
		char *str_type = return_str_type(i);
		uint8_t space_state = 19 - strlen(str_state) - 2 - strlen(str_type);
		if (i == 0)
		{
			print_port(port, info);
			printf("%s(%s)", str_state, str_type);
			print_space(space_state);
			if (info->scan_type >= SYN && info->scan_type <= XMAS)
				printf("%s\n", return_service_tcp(port->nb));
			else
				printf("%s\n", return_service_udp(port->nb));
		}
		else
			printf("          %s(%s)\n", str_state, str_type);
	}
}

void print_line(t_scan_port *port, t_info *info)
{
	if (info->scan_type == ALL)
	{
		print_all(port, info);
		return;
	}
	int state = port->state[info->scan_type];
	if (state != OPEN && state != OPEN_FILT)
		return;
	print_port(port, info);
	char *str_state = return_str_state(state);
	uint8_t space_state = 19 - strlen(str_state);

	printf("%s", str_state);
	print_space(space_state);
	if (info->scan_type >= SYN && info->scan_type <= XMAS)
		printf("%s\n", return_service_tcp(port->nb));
	else
		printf("%s\n", return_service_udp(port->nb));
}

void	super_print( t_host *host, t_info *info )
{
	printf("\n");

	printf("Scan Configurations:\n");
	printf("Nbr of Ports to scan: %d\n", info->port_range);
	printf("Nbr of threads: %d\n", info->nb_thread);
	printf("Scans to be performed: ");
	char *scan = return_str_type(info->scan_type);
	printf("%s\n\n", scan);

	while (host != NULL)
	{
		printf("HOST: %s\n", host->name);
		printf("Host is up\n");
		int not_open = info->port_range - host->open;
		if (not_open != 0)
			printf("Not shown: %d tcp ports\n", not_open);
		if (not_open != info->port_range)
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