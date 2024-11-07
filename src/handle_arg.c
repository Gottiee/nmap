#include "../inc/nmap.h"

void	print_usage( void )
{
	printf("Printing usage ... \n");
	printf("ft_nmap 1.0\n Usage: ./ft_nmap [--scan VALUE1 VALUE2 VALUE3] [--speedup number] [--ports n1/n2] --ip hostname|ip_addr.\n");
	printf("--scan: VALUE can be one of these values: SYN, NULL, ACK, FIN, XMAS, UDP. One or multiple values can be specified.\n");
	printf("--speedup: number must be a positive number less than 250 included.\n");
	printf("--ports: n1 and n2 define a range of ports to scan. Both n1 and n2 must positive number. The range defined has to be less than 1024 long.\n");
	printf("--ip: is required. hostname is a hostname and ip_addr a IPv4 ip address.\n");
}

bool	return_error( char *s_err )
{
	fprintf(stderr, "%s\n", s_err);
	return (1);
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

bool	define_scan( char ***argv, t_info *info )
{
	uint8_t	i = 0;
	char *argv_list[7] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP", NULL};

	++(*argv);
	if (*argv == NULL || **argv == NULL || ***argv == '-' || ***argv == '\0')
		return (return_error("Format error: scan: no value"));
	while ((*argv) != NULL && **argv != NULL && ***argv != '-')
	{
		for (i = 0; **argv != NULL && argv_list[i] != NULL; i++)
		{
			if (strcmp(**argv, argv_list[i]) == 0)
				break ;
		}
		switch (i)
		{
			case 0:
				info->scan_type = SYN;
				break ;
			case 1:
				info->scan_type = S_NULL;
				break ;
			case 2:
				info->scan_type = ACK;
				break ;
			case 3:
				info->scan_type = FIN;
				break ;
			case 4:
				info->scan_type = XMAS;
				break ;
			case 5:
				info->scan_type = UDP;
				break ;
			default:
			return (return_error("Format error: scan: Invalid value"));
		}
		++(*argv);
	}
	return (0);
}

bool	get_port_number( unsigned short (*port_range)[2], char *argv, bool first )
{
	uint8_t	i = 0;
	char	s[6] = {0};
	char	sep = 0;
	sep = (first == true ? '/' : '\0');

	if (argv == NULL || *argv == '\0')
		return (return_error("Format error: port: missing port number"));

	while (argv[i] && i < 6 && argv[i] != '/')
	{
		if (isdigit(argv[i]) == 0)
			return (return_error("Format error: port: Port numbers must be only numerics"));
		s[i] = argv[i];
		i++;
	}
	if (argv[i] != sep)
		return (return_error("Format error: port: Either port number is greater than 65535 or separator is different from '/'"));
	else if (strcmp(s, "0") == 0 || (strlen(s) == 5 && strcmp(s, "65535") > 0))
		return (return_error("Format error: scan: port number must be between 1 and 65535"));
	(*port_range)[!first] = atoi(s);
	return (0);
}

bool	define_ports( unsigned short (*port_range)[2], char *argv )
{
	char	*sep = NULL;
	size_t	len = 0;

	if (argv == NULL)
		return (return_error("Format error: port: no value"));
	len = strlen(argv);
	if (len == 0 || len > 11)
		return (return_error("Format error: port: value must be between 0 and 65535"));
	sep = strchr(argv, '/');
	if (sep == NULL || sep != strrchr(argv, '/'))
		return (return_error("Format error: port: must be two numbers separated by a unique '/'"));

	if (get_port_number(port_range, argv, 1))
		return (1);
	argv = sep + 1;
	if (get_port_number(port_range, argv, 0) == 1)
		return (1);
	if ((*port_range)[1] - (*port_range)[0] + 1 > 1024 || (*port_range)[0] >= (*port_range)[1])
		return (return_error("Format error: port: port range must be between 1 and 1024 written in ascending order"));
	return (0);
}

bool	init_nb_threads( char ***argv, t_info *info )
{
	size_t	i = 0;
	
	++(*argv);
	if (**argv == NULL)
		return (return_error("Format error: speedup: no value"));
	for (i = 0; (**argv)[i] != '\0'; i++)
	{
		if (isdigit((**argv)[i]) == 0)
			return (return_error("Format error: speedup: value must be numeric"));
	}
	if (i == 0)
		return (return_error("Format error: speedup: no value"));
	info->nb_thread = atoi(**argv);
	if (info->nb_thread > 250)
		return (return_error("Format error: thread: value must a positive number less than 250"));
	return(0);
}

char	**init_single_hostname( char ***argv )
{
	char	**hostnames = NULL;

	hostnames = calloc(2, sizeof(char *));
	if (hostnames == NULL)
	{
		fprintf(stderr, "ft_nmap: init_hostnames: %s\n", strerror(errno));
		return (NULL);
	}
	hostnames[1] = NULL;
	if (**argv != NULL)
	{
		if (***argv == '-')
		{
			fprintf(stderr, "ft_nmap: ip: no argument\n");
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
		fprintf(stderr, "Format error: ip: no hostname\n");
		free(hostnames);
		return (NULL);
	}
	return (hostnames);
}

char	**init_multiple_hostnames( char ***argv )
{
	char	**hostnames = NULL;
	char	*tmp = NULL;
	size_t	len_buf = 256;
	size_t n_hosts = 0;
	FILE	*fd = fopen(**argv, "r");
	if (fd == NULL)
	{
		fprintf(stderr, "ft_nmap: fopen: file not found\n");
		return (NULL);
	}
	char	*buf = calloc(len_buf, sizeof(char));
	if (buf == NULL)
	{
		perror("ft_nmap: calloc buf getline");
		return (NULL);
	}

	while (getline(&buf, &len_buf, fd) != -1)
	{
		++n_hosts;
	}
	hostnames = calloc(n_hosts + 1, sizeof(char *));
	if (hostnames == NULL)
	{
		perror("ft_nmap: calloc hostnames");
		return (NULL);
	}
	for (size_t i = 0; i < n_hosts; i++)
	{
		hostnames[i] = calloc(256, 1);
		if (hostnames[i] == NULL)
		{
			perror("ft_nmap: calloc hostnames[]");
			free(hostnames);
			return (NULL);
		}
	}
	hostnames[n_hosts] = NULL;
	fseek(fd, 0L, 0);
	for (size_t i = 0; (getline(&buf, &len_buf, fd) != -1) && i < n_hosts; i++)
	{
		strcpy(hostnames[i], buf);
		tmp = strchr(hostnames[i], '\n');
		if (tmp != NULL)
			*tmp = '\0';
	}
	
	free(buf);
	fclose(fd);
	return (hostnames);
}

char	**init_hostnames( bool single, char ***argv )
{
	char	**hostnames = NULL;

	++(*argv);
	if (single)
		hostnames = init_single_hostname(argv);
	else
	{
		hostnames = init_multiple_hostnames(argv);
	}
	return (hostnames);
}

char	**handle_arg( int argc, char ***argv, t_info *info, t_info_port *info_ports )
{
	char	**hostnames = NULL;
	char	*opt_list[] = {"help", "scan", "speedup", "ip", "ports", "file", NULL};
	uint8_t	i = 0;
	unsigned short	port_range[2] = {0};

	if (argc < 2)
		fprintf(stderr, "Format error: Invalid number of arguments\n");

	(*argv)++;
	for (int nb_arg = 0; **argv != NULL && nb_arg < argc; nb_arg++)
	{
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
				(void)error_handling(&hostnames);
				return (NULL) ;
			case 1:
				if (define_scan(argv, info) == 1)
					return (error_handling(&hostnames));
				break ;
			case 2:
				if (init_nb_threads(argv, info) == 1)
					return (error_handling(&hostnames));
				break ;
			case 3:
				hostnames = init_hostnames(true, argv);
				if (hostnames == NULL)
					return (error_handling(&hostnames));
				break ;
			case 4:
				++(*argv);
				if (define_ports(&port_range, **argv) == 1)
					return (error_handling(&hostnames));
				info_ports->nbr_of_port_scan = port_range[1] - port_range[0] + 1;
				bzero(info_ports->to_scan, 1024 * sizeof(unsigned short));
				for (unsigned short i = port_range[0]; i <= port_range[1]; i++)
					info_ports->to_scan[i - port_range[0]] = i;
				break ;
			case 5:
				hostnames = init_hostnames(false, argv);
				if (hostnames == NULL)
					return (error_handling(&hostnames));
				break ;
			default:
				printf("ft_nmap: Unrecognize option '%s'\n", **argv);
				return (error_handling(&hostnames));
		}
		if (*argv != NULL && i != 1)
			++(*argv);
	}
	return (hostnames);
}