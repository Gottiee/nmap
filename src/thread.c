#include "../inc/nmap.h"

pthread_mutex_t	g_print_lock;
pthread_mutex_t	g_lock;
bool	g_done = 0;

bool	check_g_done( void )
{
	bool	ret = 0;

	pthread_mutex_lock(&g_lock);
	ret = g_done;
	pthread_mutex_unlock(&g_lock);
	return (ret);
}

void *scan_routine(void *th_arg)
{
	// pcap_if_t *alldvsp = NULL;
	// pcap_t *handle = NULL;
	// t_scan_port *port_scan = (t_scan_port *)port_struct;
	// (void)port_scan;
	// alldvsp = init_device();
	// handle = init_handler(alldvsp->name);
	// setup_filter("dst port 443 and ip dst 54.36.91.62 and tcp", handle);
	// pcap_freealldevs(alldvsp);
	// pcap_close(handle);
	// int	port_nb = 0;
	t_thread_arg	*th_info = (t_thread_arg *)th_arg;
	int		wait_ret = 0;
	struct timespec	wait_time;
	bool	(*scans_fn[7])(t_scan_port *) = { scan_syn, scan_null, scan_ack, scan_fin, scan_xmas, scan_udp };
	// char	*scan_name[8] = { "all", "syn", "null", "ack", "fin", "xmas", "udp", NULL };
	
	pthread_mutex_lock(&th_info->lock);
	while (1)
	{
		if (check_g_done() == 1)	//	CONDITION D'ARRET DE LA BOUCLE INFINIE
			break ;
		gettimeofday((struct timeval *)&wait_time, NULL);	//	SET LA VALEUR
		wait_time.tv_sec += 1;								//	DE TIMEOUT
		while (th_info->data_ready == 0 && wait_ret != ETIMEDOUT)
		{
			//	CON
			if (check_g_done() == 1)	//	CONDITION D'ARRET DE LA BOUCLE INFINIE
				break ;
			wait_ret = pthread_cond_timedwait(&th_info->cond, &th_info->lock, &wait_time);
			if (wait_ret == ETIMEDOUT)	//	TIMEOUT ASSURE L'ARRET DE LA BOUCLE
			{
				pthread_mutex_lock(&g_print_lock);
				printf("(%d) wait timed out\n", th_info->id);
				pthread_mutex_unlock(&g_print_lock);
				break ;
			}
		}
		if (wait_ret == ETIMEDOUT)	//	QUITTE BOUCLE PRINCIPALE
			break ;
		th_info->data_ready = 0;	//	SET CONDITION POUR TIMEDWAIT
		
		pthread_mutex_lock(&g_print_lock);
		printf("(%d) Scanning port %d ... \n", th_info->id, th_info->port.nb);
		pthread_mutex_unlock(&g_print_lock);

		//	PARTIE DE SCAN
		if (th_info->scan_type == 0)
			scan_all();
		else
		{
			for (uint8_t i = 0; i <= 6; i++)	//	ITERE DANS LES BITS DE SCAN_TYPE
			{
				if ((th_info->scan_type << i) & 1)
					scans_fn[i](&(th_info->port));
			}
		}
	}
	pthread_mutex_lock(&g_print_lock);
	pthread_mutex_unlock(&th_info->lock);
	printf("(%d) end routine\n", th_info->id);
	pthread_mutex_unlock(&g_print_lock);
	return NULL;
}

bool	child_thread_main( pthread_t **threads, t_thread_arg **ths_struct, const t_info *info )
{
	*ths_struct = malloc(sizeof(t_thread_arg) * info->nb_thread);
	if (*ths_struct == NULL)
		return (return_error("ft_nmap: malloc"));
	(*threads) = malloc(sizeof(pthread_t) * info->nb_thread);
	if ((*threads) == NULL)
		return (return_error("ft_nmap: malloc"));
	// printf("%d bytes allocated\n", info->nb_thread);

	if (pthread_mutex_init(&g_print_lock, NULL) != 0)
		return (return_error("ft_nmap: mutex_init"));
	if (pthread_mutex_init(&g_lock, NULL) != 0)
		return (return_error("ft_nmap: mutex_init"));
	for (uint8_t i = 0; i < info->nb_thread; i++)
	{
		memcpy(&((*ths_struct)[i].port.ping_addr), &(info->ping_addr), sizeof(struct sockaddr_in));

		printf("(%d) memcpy -> %s\n", i, inet_ntoa((*ths_struct)[i].port.ping_addr.sin_addr));
		(*ths_struct)[i].is_free = 1;
		(*ths_struct)[i].id = i;
		(*ths_struct)[i].port.th_id = i;	//	POUR LE DEBUG
		(*ths_struct)[i].data_ready = 0;
		(*ths_struct)[i].port.sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
		if ((*ths_struct)[i].port.sockfd == -1)
			return (return_error("ft_nmap: socket"));
		(*ths_struct)[i].port.tcp_h = calloc(sizeof(struct tcphdr), 1);
		if ((*ths_struct)[i].port.tcp_h == NULL)
			return (return_error("ft_nmap: calloc"));
		(*ths_struct)[i].port.tcp_h->th_sport = 80;
		if ((*ths_struct)[i].port.sockfd == -1)
			return (return_error("ft_nmap: socket"));
		if (pthread_mutex_init(&((*ths_struct)[i].lock), NULL) != 0)
			return (return_error("ft_nmap: mutex_init"));
		if (pthread_cond_init(&((*ths_struct)[i].cond), NULL) != 0)
			return (return_error("ft_nmap: cond_init"));
		if (pthread_create(&((*threads)[i]), NULL, &scan_routine, &((*ths_struct)[i])) != 0)
			return (return_error("ft_nmap: pthread_create"));
	}
	return (0);
}

bool	closing_threading_ressources( pthread_t **threads, t_thread_arg **ths_struct, t_info *info )
{
	int	ret = 0;
	for (int i = 0; i < info->nb_thread; i++)
	{
		// pthread_mutex_lock(&g_print_lock);
		// printf("(%d) joining ... \n", i);
		// pthread_mutex_unlock(&g_print_lock);
		ret = pthread_join((*threads)[i], NULL);
		if (ret != 0)
		{
			fprintf(stderr, "pthread_join failed: %d\n", ret);
			switch(ret)
			{
				case EDEADLK:
					fprintf(stderr, "EDEALK\n");
					break ;
				case EINVAL:
					fprintf(stderr, "EINVAL\n");
					break ;
				case ESRCH:
					fprintf(stderr, "ESRCH\n");
					break ;
				default:
					fprintf(stderr, "Default\n");
					break ;
			}
			return (1);
		}
		close((*ths_struct)[i].port.sockfd);
		pthread_cond_destroy(&((*ths_struct)[i].cond));
		pthread_mutex_destroy(&((*ths_struct)[i].lock));
		// pthread_mutex_lock(&g_print_lock);
		// printf("(%d) joined\n", i);
		// pthread_mutex_unlock(&g_print_lock);
	}
	free(*threads);
	free((*ths_struct)->port.tcp_h);
	free(*ths_struct);
	return (0);
}

void threading_scan_port(t_info *info, t_host *host)
{
	(void) host;
	pthread_t	*threads = NULL;
	t_thread_arg	*ths_struct = NULL;

	printf("hostname == %s (%s)\n", info->hostnames[0], inet_ntoa(info->ping_addr.sin_addr));

	if (child_thread_main(&threads, &ths_struct, info) == 1)
		return ;

	uint16_t	port = info->first_port;
	//	BOUCLE PRINCIPALE
	while (port < info->first_port + info->port_range)
	{
		//	BOUCLE TOUS LES THREADS
		for (uint8_t th_id = 0; th_id < info->nb_thread; th_id++)
		{
			//	CHECK IF MUTEX UNLOCK WITHOUT BLOCKING
			if (pthread_mutex_trylock(&(ths_struct[th_id].lock)) == 0)
			{
				pthread_mutex_lock(&g_print_lock);
				// printf("Main > (%d) mutex locked: port == %d\n", th_id, port);
				pthread_mutex_unlock(&g_print_lock);
				ths_struct[th_id].port.nb = port;
				ths_struct[th_id].scan_type = info->scan_type;
				ths_struct[th_id].port.tcp_h->dest = htons(port);
				strlcpy(ths_struct[th_id].port.hostname, *(info->hostnames), strlen(*(info->hostnames) + 1)); 
				ths_struct[th_id].data_ready = 1;	//	CONDIITON D'ARRET DE L'ATTENTE DU CHILD
				pthread_cond_signal(&(ths_struct[th_id].cond));
				pthread_mutex_unlock(&(ths_struct[th_id].lock));
				if (++port >= 1024)	//	PROTECTION UNPEU INUTILE
					break ;
				usleep(1);		//	PEUT ETRE ENLEVE APRES TESTS
			}
		}
	}
	
	pthread_mutex_lock(&g_lock);
	g_done = 1;
	pthread_mutex_unlock(&g_lock);

	// pthread_mutex_lock(&g_print_lock);
	// printf("Infinite loop finished\n");
	// pthread_mutex_unlock(&g_print_lock);

	if (closing_threading_ressources(&threads, &ths_struct, info) == 1)
	{
		fprintf(stderr, "closing ressources failed\n");
	}

	pthread_mutex_destroy(&g_print_lock);
	pthread_mutex_destroy(&g_lock);
	printf("Leaving\n");
	// free(ports);
}