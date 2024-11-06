#include "../inc/nmap.h"

void	init_values( s_info *info )
{
	info->hostnames = NULL;
	info->nb_thread = 0;
	
}

int main( int argc, char **argv )
{
	s_info	info;
	t_info_port	info_ports;
	
	info.hostnames = handle_arg(argc, &argv, &info, &info_ports);
	if (info.hostnames == NULL)
	{
		// fprintf(stderr, "ft_nmap: Invalid usage\n");
		exit (2);
	}
	// for (unsigned short i = 0; i < info_ports.nbr_of_port_scan; i++)
	// 	printf("info_ports.to_scan[%d] == %hu\n", i, info_ports.to_scan[i]);
	
	for (uint8_t i = 0; info.hostnames[i] != NULL; i++)
		free(info.hostnames[i]);
	free(info.hostnames);
	return(0);
}