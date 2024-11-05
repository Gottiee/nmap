#include "../inc/nmap.h"

void	init_values( s_info *info )
{
	info->hostnames = NULL;
	info->nb_thread = 0;
	
}

int main( int argc, char **argv )
{
	s_info	info;
	
	info.hostnames = handle_arg(argc, &argv, &info);
	if (info.hostnames == NULL)
	{
		fprintf(stderr, "ft_nmap: Invalid usage\n");
		exit (2);
	}
	for (uint8_t i = 0; info.hostnames[i] != NULL; i++)
	{
		free(info.hostnames[i]);
	}
	free(info.hostnames);
	return(0);
}