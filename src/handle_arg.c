#include "../inc/nmap.h"

void	print_usage( void )
{
	printf("Printing usage ... \n");
}

char	**error_handling( char ***hostnames )
{
	if (*hostnames != NULL)
	{
		for (uint8_t i = 0; (*hostnames)[i] != NULL; i++)
			free((*hostnames)[i]);
		free((*hostnames));
	}
	return (NULL);
}

bool	define_scan( char ***argv, s_info *info )
{
	// printf("> Defining scan ... \n");
	uint8_t	i = 0;
	char *argv_list[7] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP", NULL};

	++(*argv);
	if (*argv == NULL || **argv == NULL || ***argv == '-' || ***argv == '\0')
	{
		fprintf(stderr, "Format error: scan: no value given\n");
		return (1);
	}
	while ((*argv) != NULL && **argv != NULL && ***argv != '-')
	{
		// printf("**argv == [%s]\n", **argv);
		for (i = 0; **argv != NULL && argv_list[i] != NULL; i++)
		{
			if (strcmp(**argv, argv_list[i]) == 0)
				break ;
		}
		// printf("i == %d\n", i);
		switch (i)
		{
			case 0:
				info->scans += SYN;
				break ;
			case 1:
				info->scans += S_NULL;
				break ;
			case 2:
				info->scans += ACK;
				break ;
			case 3:
				info->scans += FIN;
				break ;
			case 4:
				info->scans += XMAS;
				break ;
			case 5:
				info->scans += UDP;
				break ;
			default:
				fprintf(stderr, "Format error: Invalid scan option\n");
				return (1) ;
		}
		++(*argv);
	}
	return (0);
}

char	**init_hostnames( bool single, char ***argv )
{
	//	check len <= 255(including dots);
	// printf("> Initalizing hostnames ... \n");
	// printf("*argv == [%s]\n", **argv);

	char	**hostnames = NULL;

	if (single)
	{
		// printf("Single address\n");
		hostnames = calloc(2, sizeof(char *));
		if (hostnames == NULL)
		{
			fprintf(stderr, "ft_nmap: init_hostnames: %s\n", strerror(errno));
			return (NULL);
		}
		hostnames[1] = NULL;
		++(*argv);
		if (**argv != NULL)
		{
			// printf("*argv == [%s]\n", **argv);
			if (***argv == '-')
			{
				fprintf(stderr, "ft_nmap: ip: no argument given\n");
				free(hostnames);
				return (NULL);
			}
			hostnames[0] = strdup(**argv);
			if (hostnames[0] == NULL)
			{
				fprintf(stderr, "ft_nmap: init_hostnames: %s\n", strerror(errno));
				free(hostnames);
				return (NULL);
			}
		}
		else
		{
			fprintf(stderr, "Format error: ip: no hostname given\n");
			free(hostnames);
			return (NULL);
		}
	}
	else
	{
		printf("Multiple addresses\n");
	}
	return (hostnames);
}

bool	get_port_number( s_info *info, char *argv, bool first )
{
	uint8_t	i = 0;
	char	s[6] = {0};
	char	sep = 0;
	sep = (first == true ? '/' : '\0');

	if (argv == NULL || *argv == '\0')
	{
		fprintf(stderr, "Format error: missing port number\n");
		return (1);
	}

	while (argv[i] && i < 6 && argv[i] != '/')
	{
		if (isdigit(argv[i]) == 0)
		{
			fprintf(stderr, "Format error: Port numbers must be only numerics\n");
			return (1);
		}
		s[i] = argv[i];
		i++;
	}
	if (argv[i] != sep)
	{
		fprintf(stderr, "Format error: Either port number is greater than 65535 or separator is different from '/'\n");
		return (1);
	}
	info->ports[!first] = atoi(s);
	return (0);
}

bool	define_ports( s_info *info, char *argv )
{
	// printf("> Defining ports ... \n");
	// printf("argv = [%s]\n", argv);
	char	*sep = NULL;


	if (strlen(argv) > 11)
	{
		fprintf(stderr, "Format error: ports number must be between 0 and 65535\n");
		return (1);
	}
	sep = strchr(argv, '/');
	if (sep == NULL || sep != strrchr(argv, '/'))
	{
		fprintf(stderr, "Format error: Format must be two numbers separated by a unique '/'\n");
		return (1);
	}

	if (get_port_number(info, argv, 1))
		return (1);
	argv = sep + 1;
	if (get_port_number(info, argv, 0) == 1)
		return (1);
	// printf(" >>> End define_ports(): info->ports[0] == %d | info->ports[1] == %d\n", info->ports[0], info->ports[1]);
	if (info->ports[1] - info->ports[0] > 1024 || info->ports[0] >= info->ports[1])
	{
		fprintf(stderr, "Format error: port range must be between 0 and 1024 written in ascending order\n");
		return (1);
	}
	return (0);
}

bool	init_nb_threads( char ***argv, s_info *info )
{
	printf("> Initializing threads ... \n");
	size_t	i = 0;
	
	++(*argv);
	if (**argv == NULL)
	{
		fprintf(stderr, "Format error: speedup: no value given\n");
		return (1);
	}
	for (i = 0; (**argv)[i] != '\0'; i++)
	{
		if (isdigit((**argv)[i]) == 0)
		{
			fprintf(stderr, "Format error: speedup: value must be numeric\n");	
			return (1);
		}
	}
	if (i == 0)
	{
		fprintf(stderr, "Format error: speedup: no value given\n");
		return (1);
	}
	info->nb_thread = atoi(**argv);
	return(0);
}

char	**handle_arg( int argc, char ***argv, s_info *info )
{
	char	**hostnames = NULL;
	char	*opt_list[] = {"help", "scan", "speedup", "ip", "ports", NULL};
	uint8_t	i = 0;

	if (argc < 2)
		fprintf(stderr, "Format error: Invalid number of arguments\n");

	(*argv)++;
	for (int nb_arg = 0; **argv != NULL && nb_arg < argc; nb_arg++)
	{
		// printf("**argv == [%s]\n", **argv);
		if ((**argv)[0] != '-' || (**argv)[1] != '-')
		{
			fprintf(stderr, "Invalid option: [%s]\n", **argv);
			return (error_handling(&hostnames)) ;
		}
		**argv += 2;
		for (i = 0; opt_list[i] != NULL; i++)
		{
			if (strcmp(**argv, opt_list[i]) == 0)
				break ;
		}
		switch (i)
		{
			case 0:
				print_usage();
				break ;
			case 1:
				if (define_scan(argv, info) == 1)
					return (error_handling(&hostnames));
				// printf("After define_scan(): **argv == [%s]\n", **argv);
				break ;
			case 2:
				if (init_nb_threads(argv, info) == 1)
					return (error_handling(&hostnames));
				++(*argv);
				break ;
			case 3:
				hostnames = init_hostnames(true, argv);
				if (hostnames == NULL)
					return (error_handling(&hostnames));
				++(*argv);
				// printf("*argv == [%s]\n", **argv);
				break ;
			case 4:
				++(*argv);
				if (define_ports(info, **argv) == 1)
					return (error_handling(&hostnames));
				++(*argv);
				break ;
			default:
				// printf("[%s]: Unknown option\n", **argv);
				return (error_handling(&hostnames));
		}
		// if (*argv != NULL)
		// 	++(*argv);
	}

	return (hostnames);
}