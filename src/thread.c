#include "../inc/nmap.h"

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

void	alloc_values( t_thread_arg **tab_th_info, pthread_t **threads, t_info *info )
{
	*tab_th_info = calloc(info->nb_thread, sizeof(t_thread_arg));
	if (*tab_th_info == NULL)
		fatal_perror("ft_nmap: calloc tab_th_info");
	*threads = calloc(info->nb_thread, sizeof(pthread_t));
	if (*threads == NULL)
	{
		free(*tab_th_info);
		fatal_perror("ft_nmap: calloc(threads)");
	}
}

void	send_end_signal( t_thread_arg *tab_th_info, uint8_t nb_thread )
{
	for (uint8_t th_id = 0; th_id < nb_thread; th_id++)
	{
		if (pthread_mutex_lock(&(tab_th_info[th_id].lock)) == 0)
		{
			pthread_cond_signal(&tab_th_info[th_id].cond);
			pthread_mutex_unlock(&(tab_th_info[th_id].lock));
			usleep(1);
		}
	}
}

void	close_thread( pthread_t *thread, t_thread_arg *tab_th_info)
{
	int	ret = 0;

	ret = pthread_join(*thread, NULL);
	if (ret != 0)
		fatal_error("ft_nmap: pthread_join fail");
	pthread_cond_destroy(&tab_th_info->cond);
	pthread_mutex_destroy(&(tab_th_info->lock));
	close(tab_th_info->sockfd);
}

void	close_all_threads( pthread_t *threads, t_thread_arg *tab_th_info, const uint8_t nb_th )
{
	for (int i = 0; i < nb_th; i++)
	{
		if (pthread_mutex_lock(&(tab_th_info[i].lock)) == 0)
		{
			pthread_cond_signal(&tab_th_info[i].cond);
			pthread_mutex_unlock(&(tab_th_info[i].lock));
			usleep(1);
		}
		close_thread(&threads[i], &tab_th_info[i]);
		pcap_close(tab_th_info[i].handle);
	}
	if (threads)
		free(threads);
	if (tab_th_info)
		free(tab_th_info);
	
	pthread_mutex_destroy(&g_lock);
	pthread_mutex_destroy(&g_print_lock);
}

void	handle_error_init_threads( pthread_t *threads, t_thread_arg *tab_th_info, const int16_t i, char *err_str )
{
	pthread_mutex_lock(&g_lock);g_done = 1;pthread_mutex_unlock(&g_lock);
	send_end_signal(tab_th_info, i);
	close_all_threads(threads, tab_th_info, i);
	fatal_perror(err_str);
}

void	init_threads( pthread_t	*threads, t_thread_arg *tab_th_info, t_info *info )
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

	for (int16_t i = 0; i < info->nb_thread; i++)
	{
		tab_th_info[i].handle = init_handler();
		if (tab_th_info[i].handle == NULL)
		{
			handle_error_init_threads(threads, tab_th_info, i, "ft_nmap: init_handle");
		}
		tab_th_info[i].id = i;
		tab_th_info[i].index_port = 0;
		tab_th_info[i].data_ready = 0;
		tab_th_info[i].scan_type = info->scan_type[0];
		tab_th_info[i].ip_src = info->ip_src;
		tab_th_info[i].sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if (tab_th_info[i].sockfd == -1)
		{
			handle_error_init_threads(threads, tab_th_info, i, "ft_nmap: socket");
		}
		struct timeval timeout;
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		if (setsockopt(tab_th_info[i].sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0)
		{
			handle_error_init_threads(threads, tab_th_info, i, "ft_nmap: setsockopt");			
		}

		if (pthread_mutex_init(&(tab_th_info[i].lock), NULL) != 0)
		{
			handle_error_init_threads(threads, tab_th_info, i, "ft_nmap: pthread_mutex_init");			
		}
		if (pthread_cond_init(&(tab_th_info[i].cond), NULL) != 0)
		{
			fatal_perror("ft_nmap: init_threads: pthread_cond_init");
			pthread_mutex_destroy(&(tab_th_info[i].lock));
		}
		if (pthread_create(&(threads[i]), NULL, &scan_routine, &(tab_th_info[i])) != 0)
		{
			fatal_perror("ft_nmap: init_threads: pthread_create");
			pthread_cond_destroy(&(tab_th_info[i].cond));
			pthread_mutex_destroy(&(tab_th_info[i].lock));
		}
		usleep(20);
	}
}

void	*scan_routine( void *arg )
{
	t_thread_arg	*th_info = (t_thread_arg *) arg;

	pthread_mutex_lock(&(th_info->lock));
	
	do
	{
		th_info->data_ready = 0;
		while (check_g_done() == 0 && th_info->data_ready == 0)
		{
			pthread_cond_wait(&th_info->cond, &(th_info->lock));
		}
		if (check_g_done() == 1 && th_info->data_ready == 0)
			break ;
		if (scan_switch(&th_info->host->port_tab[th_info->index_port], th_info) == 1)
			break ;
	} while (check_g_done() == 0);
	pthread_mutex_unlock(&(th_info->lock));
	return (NULL);
}

void threading_scan_port(t_info *info, t_host *current_host)
{
	char	str_filter[1024] = {0};
	uint8_t scan = 0;
	int last_port = info->first_port + info->port_range;
	int	port = info->first_port;
	t_thread_arg	*tab_th_info = NULL;
	pthread_t		*threads = NULL;

	alloc_values(&tab_th_info, &threads, info);

	init_threads(threads, tab_th_info, info);

	while (current_host != NULL)
	{
		while (port < last_port)
		{
			while (scan < NB_MAX_SCAN && info->scan_type[scan] != -1)
			{
				for (uint8_t th_id = 0; port < last_port && th_id < info->nb_thread; th_id++)
				{
					usleep(200);
					if (pthread_mutex_trylock(&(tab_th_info[th_id].lock)) == 0)
					{
						if (g_done == 1)
						{
							pthread_mutex_unlock(&(tab_th_info[th_id].lock));
							goto end_main;
						}
						if (tab_th_info[th_id].data_ready == 1)
						{
							pthread_mutex_unlock(&(tab_th_info[th_id].lock));
							continue ;
						}
						tab_th_info[th_id].host = current_host;
						if (tab_th_info[th_id].host->port_tab[port - info->first_port].nb != port)
							tab_th_info[th_id].host->port_tab[port - info->first_port].nb = port;
						if (info->options.verbose == true)
						{
							pthread_mutex_lock(&g_print_lock);printf("(main) thread %d scanning host %s port %d\n", th_id, current_host->name, tab_th_info[th_id].host->port_tab[port - info->first_port].nb);pthread_mutex_unlock(&g_print_lock);
						}
						tab_th_info[th_id].index_port = port - info->first_port;
						tab_th_info[th_id].scan_type = info->scan_type[scan];
						tab_th_info[th_id].data_ready = 1;
						bzero(str_filter, IPADDR_STRLEN);
						pthread_cond_signal(&tab_th_info[th_id].cond);
						pthread_mutex_unlock(&(tab_th_info[th_id].lock));
						scan++;
						if (scan > NB_MAX_SCAN || info->scan_type[scan] == -1)
							break;
					}
				}
			}
			scan = 0;
			port++;
		}
		port = info->first_port;
		current_host = current_host->next;
	}
	pthread_mutex_lock(&g_lock);
	g_done = 1;
	pthread_mutex_unlock(&g_lock);

	end_main:
		close_all_threads(threads, tab_th_info, info->nb_thread);
		pcap_freealldevs(info->alldvsp);
}