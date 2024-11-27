#include "../inc/nmap.h"

void	init_values( t_info *info )
{
	info->hostnames = NULL;
	info->nb_thread = 0;
	info->scan_type = ALL;

	info->first_port = 0;
	info->port_range = 1024;
	// for (uint16_t i = 0; i < 1024; i++)
	// {
	// 	info->port_info->to_scan[i] = i + 1;
	// }
}

void ping_and_scan(t_info *info, struct timeval *start)
{
    t_host *start_host = NULL;
	t_host *current_host = NULL;
	int pinged = 0;
	int success = 0;

	for (int i = 0; info->hostnames[i]; i++)
	{
		if (!fill_sockaddr_in(info->hostnames[i], &info->ping_addr))
		{
			fprintf(stderr, "Failed to resolve \"%s\".\n", info->hostnames[i]);
			continue;
		}
		pinged ++;
		if (!ping_ip(&info->ping_addr))
			continue;
		success ++;
		
		if (!start_host)
		{
			start_host = init_host_list(info->hostnames[i], info);
			info->start_host = start_host;
			current_host = start_host;
		}
		else
			current_host = add_host_list(info->hostnames[i], start_host, info);
		if (info->nb_thread == 0)
			scan(&info->ping_addr, info, current_host);
	}
	if (info->nb_thread > 0)
		threading_scan_port(info, start_host);

	double second = time_till_start(start);
	printf("Nmap done: %d IP address (%d host up) scanned in %0.2f seconds\n", pinged, success, second);
}

int main( int argc, char **argv )
{
    t_info info;
	struct timeval start;

    gettimeofday(&start, NULL);

	init_values(&info);
	info.hostnames = handle_arg(argc, &argv, &info);
	if (info.hostnames == NULL)
		exit (2);

	ping_and_scan(&info, &start);
	
	super_print(info.start_host, &info);
	free_host_list(info.start_host);

	for (size_t i = 0; info.hostnames[i] != NULL; i++)
		free(info.hostnames[i]);
	free(info.hostnames);
	return(0);
}