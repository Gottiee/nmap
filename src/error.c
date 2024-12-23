#include "../inc/nmap.h"

void fatal_error(char *err)
{
    fprintf(stderr, "%s\n", err);

	free_host_list(g_info->start_host);
	free_host_tab_str(g_info->hostnames);
	pcap_freealldevs(g_info->alldvsp);

    exit(1);
}

void fatal_perror(char *err)
{
	if (errno)
		perror(err);
	else
		fprintf(stderr, "%s\n", err);

	free_host_list(g_info->start_host);
	free_host_tab_str(g_info->hostnames);
	pcap_freealldevs(g_info->alldvsp);
	
    exit(2);
}

void fatal_error_str(char *message, char *err)
{
    fprintf(stderr, message, err);

	free_host_list(g_info->start_host);
	free_host_tab_str(g_info->hostnames);
	pcap_freealldevs(g_info->alldvsp);
	
	exit(3);
}