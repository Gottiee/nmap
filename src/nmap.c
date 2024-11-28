#include "../inc/nmap.h"

void	init_values( t_info *info )
{
	info->hostnames = NULL;
	info->nb_thread = 0;
	info->scan_type = ALL;
	info->nb_host_ping = 0;
	info->nb_host_ping_success = 0;

	info->first_port = 1;
	info->port_range = 1024;
}

void ping_and_scan(t_info *info)
{
    t_host *start_host = NULL;
    t_host *current_host = NULL;

    for (int i = 0; info->hostnames[i]; i++)
    {
        if (!fill_sockaddr_in(info->hostnames[i], &info->ping_addr))
        {
            fprintf(stderr, "Failed to resolve \"%s\".\n", info->hostnames[i]);
            continue;
        }
        info->nb_host_ping ++;
        if (!ping_ip(&info->ping_addr))
            continue;
        info->nb_host_ping_success ++;
        
        printf("hostname[%d]: [%s]\n", i, info->hostnames[i]);
        if (!start_host)
        {
            start_host = init_host_list(info->hostnames[i], info);
            memcpy(&start_host->ping_addr, &info->ping_addr, sizeof(struct sockaddr_in));
            info->start_host = start_host;
            current_host = start_host;
        }
        else
            current_host = add_host_list(info->hostnames[i], start_host, info);
        if (info->nb_thread == 0)
            scan(info, current_host);
    }
    if (info->nb_thread > 0)
        threading_scan_port(info, start_host);

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