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
	pcap_t *handle = NULL;
	// t_scan_port *port_scan = (t_scan_port *)port_struct;
	// (void)port_scan;
	// alldvsp = init_device();
	// handle = init_handler(alldvsp->name);
	// setup_filter("dst port 443 and ip dst 54.36.91.62 and tcp", handle);
	// pcap_freealldevs(alldvsp);
	// pcap_close(handle);
	// int	port_nb = 0;
	t_thread_arg	*th_info = (t_thread_arg *)th_arg;
	bool	(*scans_fn[7])(t_scan_port *) = { scan_syn, scan_null, scan_ack, scan_fin, scan_xmas, scan_udp };
	// char	*scan_name[8] = { "all", "syn", "null", "ack", "fin", "xmas", "udp", NULL };

	// alldvsp = init_device();
	handle = init_handler("enp0s3");
	
	
	// pthread_mutex_lock(&th_info->lock);
	while (1)
	{
		pthread_mutex_lock(&g_print_lock);
		printf("(%d) max_port  == %u | port_nb == %hu\n", th_info->id ,th_info->max_port, th_info->port.nb);
		pthread_mutex_unlock(&g_print_lock);
		if (th_info->max_port - th_info->port.nb < th_info->id)
		{
			pthread_mutex_lock(&g_print_lock);
			printf("(%d) id > reste: rest: %d\n", th_info->id, th_info->max_port - th_info->port.nb);
			pthread_mutex_unlock(&g_print_lock);
			break ;
		}
		pthread_mutex_lock(&g_print_lock);
		printf("(%d) Waiting ... \n", th_info->id);
		printf("(%d) id >= reste: rest: %d\n", th_info->id, th_info->max_port - th_info->port.nb);
		pthread_mutex_unlock(&g_print_lock);
		if (pthread_cond_wait(&th_info->cond, &th_info->lock) != 0)
			perror("pthread wait error");
		if (check_g_done() == 1)	//	CONDITION D'ARRET DE LA BOUCLE INFINIE
			break ;

		//	PARTIE DE SCAN
		setup_filter("dst port 443 and ip dst 54.36.91.62 and tcp", handle);

		if (th_info->scan_type == 0)
		{
			pthread_mutex_lock(&g_print_lock);
			printf("(%d) Scanning %hu ...  \n", th_info->id, th_info->port.nb);
			pthread_mutex_unlock(&g_print_lock);
			scan_all(th_info->id);
		}
		else
		{
			for (uint8_t i = 0; i <= 6; i++)	//	ITERE DANS LES BITS DE SCAN_TYPE
			{
				if ((th_info->scan_type << i) & 1)
					scans_fn[i](&(th_info->port));
			}
		}
	}
	pcap_close(handle);
	pthread_mutex_unlock(&th_info->lock);
	printf("(%d) Leaving thread\n", th_info->id);
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

	if (pthread_mutex_init(&g_print_lock, NULL) != 0)
		return (return_error("ft_nmap: mutex_init"));
	if (pthread_mutex_init(&g_lock, NULL) != 0)
		return (return_error("ft_nmap: mutex_init"));
	for (uint8_t i = 1; i < info->nb_thread + 1; i++)
	{
		memcpy(&((*ths_struct)[i].port.ping_addr), &(info->ping_addr), sizeof(struct sockaddr_in));

		(*ths_struct)[i].id = i;
		(*ths_struct)[i].port.th_id = i;	//	POUR LE DEBUG
		(*ths_struct)[i].port.sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
		(*ths_struct)[i].max_port = info->first_port + info->port_range - 1;
		// printf("main init: first_port == %d | range == %d | max_port == %d\n",
		// 			info->first_port, info->port_range, (*ths_struct)[i].max_port);
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
		pthread_mutex_lock(&((*ths_struct)[i].lock));
		if (pthread_create(&((*threads)[i]), NULL, &scan_routine, &((*ths_struct)[i])) != 0)
			return (return_error("ft_nmap: pthread_create"));
	}
	return (0);
}

bool	closing_threading_ressources( pthread_t **threads, t_thread_arg **ths_struct, t_info *info )
{
	int	ret = 0;
	for (int i = 1; i < info->nb_thread + 1; i++)
	{
		// if (pthread_mutex_trylock(&((*ths_struct)[i].lock)) == 0)
		// {
		// 	pthread_cond_signal(&((*ths_struct)[i].cond));
		// 	pthread_mutex_unlock(&((*ths_struct)[i].lock));
		// }
		
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
	printf("(main) first_port == %d\n", port);
	//	BOUCLE PRINCIPALE
	while (port < info->first_port + info->port_range)
	{
		//	BOUCLE TOUS LES THREADS
		for (uint8_t th_id = 1; port < info->first_port + info->port_range && th_id < info->nb_thread + 1; th_id++)
		{
			//	CHECK IF MUTEX UNLOCK WITHOUT BLOCKING
			if (pthread_mutex_trylock(&(ths_struct[th_id].lock)) == 0)
			{
				pthread_mutex_lock(&g_print_lock);
				printf("Main > (%d) mutex locked: port == %d\n", th_id, port);
				pthread_mutex_unlock(&g_print_lock);
				ths_struct[th_id].port.nb = port;
				ths_struct[th_id].scan_type = info->scan_type;
				ths_struct[th_id].port.tcp_h->dest = htons(port);
				memcpy(ths_struct[th_id].port.hostname, *(info->hostnames), strlen(*(info->hostnames)) + 1); 
				printf("(main) signal sent to %d\n", th_id);
				pthread_cond_signal(&(ths_struct[th_id].cond));
				pthread_mutex_unlock(&(ths_struct[th_id].lock));
				if (++port >= 1024)	//	PROTECTION UN PEU INUTILE
					break ;
				usleep(1);		//	PEUT ETRE ENLEVE APRES TESTS
			}
		}
	}

	pthread_mutex_lock(&g_lock);
	g_done = 1;
	pthread_mutex_unlock(&g_lock);

	if (closing_threading_ressources(&threads, &ths_struct, info) == 1)
		fprintf(stderr, "closing ressources failed\n");

	pthread_mutex_destroy(&g_print_lock);
	pthread_mutex_destroy(&g_lock);
}