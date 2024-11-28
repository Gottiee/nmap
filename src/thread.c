#include "../inc/nmap.h"

long int g_main_tid;
pthread_mutex_t	g_print_lock;
pthread_mutex_t	g_lock;
bool	g_done = 0;

void	*scan_routine( void *arg );

bool	check_g_done( void )
{
	bool	ret = 0;

	pthread_mutex_lock(&g_lock);
	ret = g_done;
	pthread_mutex_unlock(&g_lock);
	return (ret);
}

void	alloc_values( t_thread_arg **tab_th_info, pthread_t ** threads, t_info *info )
{
	*tab_th_info = calloc(info->nb_thread, sizeof(t_thread_arg));
	if (tab_th_info == NULL)
		fatal_perror("ft_nmap: calloc tab_th_info");
	*threads = calloc(info->nb_thread, sizeof(pthread_t));
	if (threads == NULL)
	{
		free(tab_th_info);
		fatal_perror("ft_nmap: calloc(threads)");
	}
}

void	send_end_signal( t_thread_arg *tab_th_info, uint8_t nb_thread )
{
	//	FERMER LES THREADS
	for (int16_t th_id = 0; th_id < nb_thread; th_id++)
	{
		if (pthread_mutex_lock(&(tab_th_info[th_id].lock)) == 0)
		{
			pthread_cond_signal(&tab_th_info[th_id].cond);
			pthread_mutex_unlock(&(tab_th_info[th_id].lock));
			usleep(1);
		}
	}
}

void	close_threads( pthread_t *threads, t_thread_arg *tab_th_info, const uint8_t nb_th, pcap_if_t *alldsvp)
{
	int	ret = 0;
	for (int i = 0; i < nb_th; i++)
	{
		ret = pthread_join(threads[i], NULL);
		if (ret != 0)
			fatal_error("ft_nmap: pthread_join fail");
		pthread_cond_destroy(&(tab_th_info[i].cond));
		pthread_mutex_destroy(&(tab_th_info[i].lock));
		close(tab_th_info[i].sockfd);
		pcap_close(tab_th_info[i].host->handle);
	}
	if (threads)
		free(threads);
	if (tab_th_info)
		free(tab_th_info);
	
	pthread_mutex_destroy(&g_lock);
	pthread_mutex_destroy(&g_print_lock);
	pcap_freealldevs(alldsvp);
}

void	init_threads( pthread_t	*threads, t_thread_arg *tab_th_info, t_info *info, pcap_if_t *alldvsp)
{

	if (pthread_mutex_init(&g_print_lock, NULL) != 0)
	{
		free(threads);
		free(tab_th_info);
		fatal_perror("ft_nmap: mutex_init");
	}
	if (pthread_mutex_init(&g_lock, NULL) != 0)
	{
		pthread_mutex_destroy(&g_print_lock);
		free(threads);
		free(tab_th_info);
		fatal_perror("ft_nmap: mutex_init");
	}

	g_done = 0;

	alldvsp = init_device(info);

	for (int16_t i = 0; i < info->nb_thread; i++)
	{
		pcap_t *handle = NULL;
		handle = init_handler(info->device);
		tab_th_info[i].handle = handle;
		tab_th_info[i].id = i;
		tab_th_info[i].index_port = 0;
		tab_th_info[i].data_ready = 0;
		tab_th_info[i].scan_type = info->scan_type;
		tab_th_info[i].sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if (tab_th_info[i].sockfd == -1)
		{
			send_end_signal(tab_th_info, i - 1);
			close_threads(threads, tab_th_info, i - 1, alldvsp);
			fatal_perror("ft_nmap: socket");
		}
		struct timeval timeout;
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		if (setsockopt(tab_th_info[i].sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0)
		{
			perror("Error");
		}


		if (pthread_mutex_init(&(tab_th_info[i].lock), NULL) != 0)
		{
			close(tab_th_info[i].sockfd);
			send_end_signal(tab_th_info, i - 1);
			close_threads(threads, tab_th_info, i - 1, alldvsp);
			fatal_perror("ft_nmap: init_threads: mutex init");
		}
		if (pthread_cond_init(&(tab_th_info[i].cond), NULL) != 0)
		{
			close(tab_th_info[i].sockfd);
			pthread_mutex_destroy(&(tab_th_info[i].lock));
			send_end_signal(tab_th_info, i - 1);
			close_threads(threads, tab_th_info, i - 1, alldvsp);
			fatal_perror("ft_nmap: init_threads: mutex init");
		}
		if (pthread_create(&(threads[i]), NULL, &scan_routine, &(tab_th_info[i])) != 0)
		{
			close(tab_th_info[i].sockfd);
			pthread_cond_destroy(&(tab_th_info[i].cond));
			pthread_mutex_destroy(&(tab_th_info[i].lock));
			send_end_signal(tab_th_info, i - 1);
			close_threads(threads, tab_th_info, i - 1, alldvsp);
			fatal_perror("ft_nmap: init_threads: thread_create");
		}
		usleep(20);
	}
}

void	*scan_routine( void *arg )
{
	t_thread_arg	*th_info = (t_thread_arg *) arg;

	pthread_mutex_lock(&(th_info->lock));
	while (check_g_done() == 0)
	{
		th_info->data_ready = 0;
		while (check_g_done() == 0 && th_info->data_ready == 0)
		{
			pthread_cond_wait(&th_info->cond, &(th_info->lock));
		}
		if (check_g_done() == 1 && th_info->data_ready == 0)
			break ;
// pthread_mutex_lock(&g_print_lock);printf("(%d) Scanning %d ...\n", th_info->id, th_info->host->port_tab[th_info->index_port].nb);pthread_mutex_unlock(&g_print_lock);
		th_info->host->port_tab[th_info->index_port].sockfd = th_info->sockfd;
		scan_switch(&th_info->host->port_tab[th_info->index_port], th_info->host, th_info->scan_type, th_info->id);
	}
	pthread_mutex_unlock(&(th_info->lock));
	return (NULL);
}

void threading_scan_port(t_info *info, t_host *current_host)
{
	pcap_if_t *alldvsp = NULL;
	int last_port = info->first_port + info->port_range;
	int	port = info->first_port;
	t_thread_arg	*tab_th_info = NULL;
	pthread_t		*threads = NULL;
	alloc_values(&tab_th_info, &threads, info);
	g_main_tid = syscall(SYS_gettid);
	g_handle = malloc(sizeof(pcap_t *) * info->nb_thread);

	init_threads(threads, tab_th_info, info, alldvsp);
	// printf("thread(main): s_addr = %s\n", inet_ntoa(current_host->ping_addr.sin_addr));

	while (current_host != NULL)
	{
		while (port < last_port)
		{
			for (int16_t th_id = 0; port < last_port && th_id < info->nb_thread; th_id++)
			{
				if (pthread_mutex_trylock(&(tab_th_info[th_id].lock)) == 0)
				{
					if (tab_th_info[th_id].data_ready == 1)
					{
						pthread_mutex_unlock(&(tab_th_info[th_id].lock));
						continue ;
					}
					tab_th_info[th_id].host = current_host;
					tab_th_info[th_id].host->ip_src = info->ip_src;
					tab_th_info[th_id].host->port_tab[port - info->first_port].nb = port;
					tab_th_info[th_id].host->port_tab[port - info->first_port].handle = tab_th_info[th_id].handle;
					tab_th_info[th_id].index_port = port - info->first_port;
					tab_th_info[th_id].data_ready = 1;
					pthread_cond_signal(&tab_th_info[th_id].cond);
// pthread_mutex_lock(&g_print_lock);printf("(main) Signal sent: id:%d, port:%d  ...\n", th_id, tab_th_info[th_id].host->port_tab[port - info->first_port].nb);pthread_mutex_unlock(&g_print_lock);
					pthread_mutex_unlock(&(tab_th_info[th_id].lock));
					port++;
					usleep(10);
				}
			}
		}
		current_host = current_host->next;
	}
	
	pthread_mutex_lock(&g_lock);
	g_done = 1;
	pthread_mutex_unlock(&g_lock);

	send_end_signal(tab_th_info, info->nb_thread);
	close_threads(threads, tab_th_info, info->nb_thread, alldvsp);
}