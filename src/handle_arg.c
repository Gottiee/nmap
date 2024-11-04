#include "../inc/nmap.h"

void	print_usage( void )
{
	printf("Printing usage ... \n");
}

void	define_scan( char ***scans )
{
	printf("Defining scan ... \n");
	while (*scans !+ NULL && (*scans)[0] != '-')
	{
		switch (*scans)
		{
			case 'syn':
				info->scans += SYN;
				break ;
			case 'null':
				info->scans += NULL;
				break ;
			case 'ack':
				info->scans += ACK;
				break ;
			case 'FIN':
				info->scans += FIN;
				break ;
			case 'xmas':
				info->scans += XMAS;
				break ;
			case 'udp':
				info->scans += UDP;
				break ;
			default:
				printf("NOT A SCAN\n");
				break ;
		}
		++(*scans);
	}
}

bool	init_hostnames( s_info *info, bool single, char *argv ){
	if (single)
	{
		printf("Single address\n");
		info->hostnames = calloc(2, sizeof(char *));
		if (info->hostnames == NULL)
		{
			fprintf(stderr, "ft_nmap: init_hostnames: %s\n", strerror(errno));
			return (1);
		}
		info->hostnames[1] = NULL;
		info->hostnames[0] = strdup(argv);
		if (info->hostnames[0] == NULL)
		{
			fprintf(stderr, "ft_nmap: init_hostnames: %s\n", strerror(errno));
			return (1);
		}
	}
	else
	{
		printf("Multiple addresses\n");
	}
	return (0);
}

bool	define_ports( s_info *info, char *argv )
{
	
}

char	*handle_arg( int argc, s_info *info, char **argv )
{
	char	**hostnames = NULL;

	if (argc < 3)
		fprintf(stderr, "Invalid number of arguments\n");

	argv++;
	while (*argv != NULL)
	{
		if ((*argv)[0] != '-' || (*argv)[1] != '-')
		{
			fprintf(stderr, "Invalid option: [%s]\n", *argv);
		}
		*argv += 2;
		switch (*argv)
		{
			case 'help':
				print_usage();
				break ;
			case 'scan':
				define_scan();
				break ;
			case 'speedup':
				info->nb_thread = ++argv;
				break ;
			case 'ip':
				if (init_hostnames(info, true, *argv) == 1)
					return (NULL);
				break ;
			case 'ports':
				if (*argv)
				{
					define_port(argv);
				}
		}
		++argv
	}

	return (hostnanes);
}