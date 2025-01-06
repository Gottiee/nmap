#include "../inc/nmap.h"

bool	parsing_return_error( char *s_err )
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
	uint8_t	nb_scan = 0;
	char *argv_list[8] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP", "ALL", NULL};
	errno = 0;

	++(*argv);
	if (*argv == NULL || **argv == NULL || ***argv == '-' || ***argv == '\0')
		return (return_error("Format error: scan: no value"));
	for (uint8_t i = 0; i < NB_MAX_SCAN; i++)
	{
		info->scan_type[i] = -1;
	}
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
				info->scan_type[nb_scan] = SYN;
				break ;
			case 1:
				info->scan_type[nb_scan] = S_NULL;
				break ;
			case 2:
				info->scan_type[nb_scan] = ACK;
				break ;
			case 3:
				info->scan_type[nb_scan] = FIN;
				break ;
			case 4:
				info->scan_type[nb_scan] = XMAS;
				break ;
			case 5:
				info->scan_type[nb_scan] = UDP;
				break ;
			case 6:
				for (uint8_t i = 0; i < NB_MAX_SCAN; i++)
				{
					info->scan_type[i] = i;
				}
				break ;
			default:
				return (parsing_return_error("Format error: scan: must be within this list -> SYN, NULL, ACK, FIN, XMAS, UDP"));
		}
		nb_scan++;
		++(*argv);
	}
	info->nb_scan_type = nb_scan;
	return (0);
}

bool	get_port_number( unsigned short (*port_range)[2], char *argv, bool first )
{
	uint8_t	i = 0;
	char	s[6] = {0};
	char	sep = 0;
	sep = (first == 1 ? '/' : '\0');
	errno = 0;

	if (argv == NULL || *argv == '\0')
		return (return_error("Format error: port: missing port number"));

	while (argv[i] && i < 6 && argv[i] != '/')
	{
		if (isdigit(argv[i]) == 0)
			return (return_error("Format error: port: Port numbers must be only numerics"));
		s[i] = argv[i];
		i++;
	}
	if (argv[i] != sep && argv[i] != '\0')
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
	errno = 0;

	if (argv == NULL)
		return (return_error("Format error: port: no value"));
	len = strlen(argv);
	if (len == 0 || len > 11)
		return (return_error("Format error: port: value must be between 0 and 65535"));
	sep = strchr(argv, '/');
	if (sep != strrchr(argv, '/'))
		return (return_error("Format error: port: must be two numbers separated by a unique '/'"));
	if (get_port_number(port_range, argv, 1) == 1)
		return (1);
	if (sep != NULL)
	{
		argv = sep + 1;
		if (get_port_number(port_range, argv, 0) == 1)
			return (1);
		if ((*port_range)[1] - (*port_range)[0] + 1 > 1024 || (*port_range)[0] >= (*port_range)[1])
			return (return_error("Format error: port: port range must be between 1 and 1024 written in ascending order"));
	}
	else
		(*port_range)[1] = (*port_range)[0];
	return (0);
}

bool	init_nb_threads( char ***argv, t_info *info )
{
	size_t	i = 0;
	errno = 0;
	
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
	info->real_threads = atoi(**argv);
	if (info->nb_thread > 250)
		return (return_error("Format error: thread: value must a positive number less than 250"));
	return(0);
}

char	**init_single_hostname( char ***argv )
{
	char	**hostnames = NULL;
	errno = 0;

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
	errno = 0;

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
	errno = 0;

	++(*argv);
	if (single)
		hostnames = init_single_hostname(argv);
	else
		hostnames = init_multiple_hostnames(argv);
	return (hostnames);
}

bool	define_nb_retries( char ***argv, t_info *info )
{
	size_t	i = 0;
	errno = 0;
	
	++(*argv);
	printf("arg define == %s\n", **argv);
	if (**argv == NULL)
		return (return_error("Format error: max-retries: no value"));
	for (i = 0; (**argv)[i] != '\0'; i++)
	{
		if (isdigit((**argv)[i]) == 0)
			return (return_error("Format error: max-retries: value must be numeric"));
	}
	if (i == 0)
		return (return_error("Format error: max-retries: no value"));
	info->options.nb_retries = atoi(**argv);
	if (info->options.nb_retries > 250)
		return (return_error("Format error: max-retries: value must a positive number less than 250"));
	else if (info->options.nb_retries == 0)
		info->options.nb_retries = 1;	
	return(0);
}

bool	define_ttl( char ***argv, t_info *info )
{
	size_t	i = 0;
	errno = 0;
	
	++(*argv);
	if (**argv == NULL)
		return (return_error("Format error: ttl: no value"));
	for (i = 0; (**argv)[i] != '\0'; i++)
	{
		if (isdigit((**argv)[i]) == 0)
			return (return_error("Format error: ttl: value must be numeric"));
	}
	if (i == 0)
		return (return_error("Format error: ttl:no value"));
	info->options.ttl = atoi(**argv);
	// if (info->options.ttl == 0 ||  info->options.ttl > 255)
	if (info->options.ttl > 255)
		return (return_error("Format error: ttl: value must a strictly positive number less than 250"));
	return(0);
}

void	generate_ipv4( char *hostname )
{
	uint	tmp = 0;
	char	*s_tmp = NULL;
	
	for (uint i = 0; i < 4; i++)
	{
		tmp = rand() % 255;
		s_tmp = ft_itoa(tmp);
		strcat(hostname, s_tmp);
		if (i != 3)
			strcat(hostname, ".");
		free(s_tmp);
	}
}

char **define_random_target( char ***argv )
{
	char	**hostnames = NULL;
	size_t	random = 0;
	size_t	i = 0;
	errno = 0;
	
	++(*argv);
	if (**argv == NULL)
	{
		perror("ft_nmap: rand-target: no value");
		return (NULL);
	}
	for (i = 0; (**argv)[i] != '\0'; i++)
	{
		if (isdigit((**argv)[i]) == 0)
		{
			perror("ft_nmap: rand-target: must be a number");
			return (NULL);
		}
	}
	if (i == 0)
	{
		perror("ft_nmap: rand-target: no value");
		return (NULL);
	}

	random = atoi(**argv);
	if (random == 0)
	{
		perror("ft_nmap: rand-target: must be strictly positive");
		return (NULL);
	}
	hostnames = calloc(random + 1, sizeof(char *));
	if (hostnames == NULL)
	{
		perror("ft_nmap: calloc hostnames");
		return (NULL);
	}
	for (size_t i = 0; i < random; i++)
	{
		hostnames[i] = calloc(16, 1);
		if (hostnames[i] == NULL)
		{
			perror("ft_nmap: calloc hostnames[]");
			free(hostnames);
			return (NULL);
		}
		generate_ipv4(hostnames[i]);
	}
	
	return (hostnames);
}

char	**handle_arg( int argc, char ***argv, t_info *info )
{
	char	**hostnames = NULL;
	char	*opt_list[] = {"help", "scan", "speedup", "ip", "ports", "file", "max-retries", "ttl", "no-ping", "rand-target", "interface", "verbose", NULL};
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
				if (hostnames == NULL)
					hostnames = init_hostnames(1, argv);
				else
					*argv += 1;
				if (hostnames == NULL)
					return (error_handling(&hostnames));
				break ;
			case 4:
				++(*argv);
				if (define_ports(&port_range, **argv) == 1)
					return (error_handling(&hostnames));
				info->port_range = port_range[1] - port_range[0] + 1;
				info->first_port = port_range[0];
				break ;
			case 5:
				if (hostnames == NULL)
					hostnames = init_hostnames(0, argv);
				else
					*argv += 1;
				if (hostnames == NULL)
					return (error_handling(&hostnames));
				break ;
			case 6:
				if (define_nb_retries(argv, info) == 1)
					return (error_handling(&hostnames));
				break ;
			case 7:
				if (define_ttl(argv, info) == 1)
					return (error_handling(&hostnames));
				break ;
			case 8:
				info->options.ping = false;
				break ;
			case 9:
				if (info->hostnames == NULL)
					hostnames = define_random_target(argv);
				else
					*argv += 1;
				if (hostnames == NULL)
					return (error_handling(&hostnames));
				break ;
			case 10:
				++(*argv);
				info->options.interface = **argv;
				break ;
			case 11:
				info->options.verbose = true;
				break ;
			default:
				fprintf(stderr, "ft_nmap: Unrecognize option '%s'\n", **argv);
				return (error_handling(&hostnames));
		}
		if (*argv != NULL && i != 1)
			++(*argv);
	}
	uint t = 0;
	if (info->real_threads > 0)
	{
		for ( ; hostnames[t] != NULL; t++){}
		info->nb_thread = info->port_range * info->nb_scan_type * t;
	}
	return (hostnames);
}