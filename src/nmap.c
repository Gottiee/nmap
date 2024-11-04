#include "../inc/nmap.h"

void	init_values( s_info *info )
{
	info->hostnames = NULL;
	info->nb_thread = 0;
	
}

int main( int argc, char **argv )
{
	s_info	info;
	
	info.hostnames = handle_arg(argc, argv);
	if (info.hostnames == NULL)
	{
		fprintf(stderr, "ft_nmap: Invalid usage\n");
		exit (2);
	}
	return(0);
}