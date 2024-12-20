#include "../inc/nmap.h"

void	init_values( t_info *info )
{
	info->hostnames = NULL;
	info->nb_thread = 0;
	for (uint8_t i = 0; i < NB_MAX_SCAN; i++)
	{
		info->scan_type[i] = i;
	}
	info->nb_host_ping = 0;
	info->nb_host_ping_success = 0;

	info->first_port = 1;
	info->port_range = 1024;

	info->options.ping = true;
	info->options.random = false;
	info->options.nb_retries = 2;
	info->options.interface = NULL;
	info->options.ttl = IPDEFTTL;

}

void ping_and_scan(t_info *info)
{
	t_host *start_host = NULL;
	t_host *current_host = NULL;
	pcap_if_t *alldvsp = NULL;
	pcap_t *handle = NULL;

	if (info->nb_thread == 0)
	{
		alldvsp = init_device(info);
		handle = init_handler("any");
	}
	for (int i = 0; info->hostnames[i]; i++)
	{
		if (!fill_sockaddr_in(info->hostnames[i], &info->ping_addr))
		{
			if (strlen(info->hostnames[i]) != 0)
				fprintf(stderr, "Failed to resolve \"%s\".\n", info->hostnames[i]);
			continue;
		}
		info->nb_host_ping ++;
		if (!ping_ip(&info->ping_addr))
			continue;
		info->nb_host_ping_success ++;
		
		if (!start_host)
		{
			start_host = init_host_list(info->hostnames[i], info);
			memcpy(&start_host->ping_addr, &info->ping_addr, sizeof(struct sockaddr_in));
			info->start_host = start_host;
			current_host = start_host;
		}
		else
		{
			current_host = add_host_list(info->hostnames[i], start_host, info);
			memcpy(&current_host->ping_addr, &info->ping_addr, sizeof(struct sockaddr_in));
		}
		if (info->nb_thread == 0)
			scan(&info->ping_addr, info, current_host, handle, alldvsp);
	}
	if (info->nb_thread > 0)
		threading_scan_port(info, start_host);
	else
	{
		pcap_freealldevs(alldvsp);
		pcap_close(handle);
	}
}

int main( int argc, char **argv )
{
    t_info info;

    gettimeofday(&info.time_start, NULL);

	init_values(&info);
	info.hostnames = handle_arg(argc, &argv, &info);
	if (info.hostnames == NULL)
		exit (2);

	ping_and_scan(&info);
	
	super_print(info.start_host, &info);
	free_host_list(info.start_host);

	for (size_t i = 0; info.hostnames[i] != NULL; i++)
		free(info.hostnames[i]);
	free(info.hostnames);
	return(0);
}