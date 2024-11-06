#include "../inc/nmap.h"

void	init_values( t_info *info )
{
	info->hostnames = NULL;
	info->nb_thread = 0;
}

void ping_and_scan(t_info *info, struct timeval *start)
{
    t_host *start_host = NULL;
	t_host *current_host = NULL;
    struct sockaddr_in ping_addr;
	int pinged = 0;
	int success = 0;


	for (int i = 0; info->hostnames[i]; i++)
	{
		if (!fill_sockaddr_in(info->hostnames[i], &ping_addr))
		{
			fprintf(stderr, "Failed to resolve \"%s\".\n", info->hostnames[i]);
			continue;
		}
		pinged ++;
		if (!ping_ip(&ping_addr))
			continue;
		success ++;
		
		if (!start_host)
		{
			start_host = init_host_list(info->hostnames[i]);
			current_host = start_host;
		}
		else
			current_host = add_host_list(info->hostnames[i], start_host);
		if (info->nb_thread > 0)
			threading_scan_port(info, current_host);
	}

	double second = time_till_start(start);
	printf("Nmap done: %d IP address (%d host up) scanned in %0.2f seconds\n", pinged, success, second);
	// free la list chainee
}

int main( int argc, char **argv )
{
    t_info info;
	t_info_port	info_ports;
	struct timeval start;

    gettimeofday(&start, NULL);
    info.port_info = &info_ports;
	init_values(&info);
	info.hostnames = handle_arg(argc, &argv, &info, &info_ports);
	if (info.hostnames == NULL)
	{
		// fprintf(stderr, "ft_nmap: Invalid usage\n");
		exit (2);
	}
	// for (unsigned short i = 0; i < info_ports.nbr_of_port_scan; i++)
	// 	printf("info_ports.to_scan[%d] == %hu\n", i, info_ports.to_scan[i]);
	ping_and_scan(&info, &start);
	for (uint8_t i = 0; info.hostnames[i] != NULL; i++)
		free(info.hostnames[i]);
	free(info.hostnames);
	return(0);
}