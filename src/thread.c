#include "../inc/nmap.h"

pthread_mutex_t	g_print_lock;
pthread_mutex_t	g_lock;
// pthread_cond_t	g_cond;
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
	*threads = calloc(info->nb_thread, sizeof(t_thread_arg));
	if (threads == NULL)
	{
		free(tab_th_info);
		fatal_perror("ft_nmap: calloc(threads)");
	}
}

void	free_struct( void *threads, void *tab_th )
{
	free(threads);
	free(tab_th);
}

void	close_threads( pthread_t *threads, t_thread_arg *tab_th_info, const uint8_t nb_th )
{
	int	ret = 0;
	for (int i = 0; i < nb_th; i++)
	{
		ret = pthread_join(threads[i], NULL);
		if (ret != 0)
			fatal_error("ft_nmap: pthread_join fail");
		pthread_cond_destroy(&(tab_th_info[i].cond));
		pthread_mutex_destroy(&(tab_th_info[i].lock));
	}
	free(threads);
	free(tab_th_info);
	
	pthread_mutex_destroy(&g_lock);
	pthread_mutex_destroy(&g_print_lock);
}

void	init_threads( pthread_t	*threads, t_thread_arg *tab_th_info, t_info *info )
{
	if (pthread_mutex_init(&g_print_lock, NULL) != 0)
	{
		free_struct(threads, tab_th_info);
		fatal_perror("ft_nmap: mutex_init");
	}
	if (pthread_mutex_init(&g_lock, NULL) != 0)
	{
		pthread_mutex_destroy(&g_print_lock);
		free_struct(threads, tab_th_info);
		fatal_perror("ft_nmap: mutex_init");
	}


	for (uint8_t i = 0; i < info->nb_thread; i++)
	{
		memcpy(&(tab_th_info[i].port.ping_addr), &(info->ping_addr), sizeof(struct sockaddr_in));

		tab_th_info[i].id = i;
		tab_th_info[i].port.nb = 0;
		tab_th_info[i].data_ready = 0;
		tab_th_info[i].scan_type = info->scan_type;

		if (pthread_mutex_init(&(tab_th_info[i].lock), NULL) != 0)
		{
			free_struct(threads, tab_th_info);
			fatal_perror("ft_nmap: init_threads: mutex init");
		}
		if (pthread_cond_init(&(tab_th_info[i].cond), NULL) != 0)
		{
			pthread_mutex_destroy(&(tab_th_info[i].lock));
			pthread_mutex_destroy(&g_lock);
			pthread_mutex_destroy(&g_print_lock);
			free_struct(threads, tab_th_info);
			fatal_perror("ft_nmap: init_threads: mutex init");
		}
		if (pthread_create(&(threads[i]), NULL, &scan_routine, &(tab_th_info[i])) != 0)
		{
			pthread_mutex_destroy(&g_lock);
			pthread_mutex_destroy(&g_print_lock);
			pthread_cond_destroy(&(tab_th_info[i].cond));
			pthread_mutex_destroy(&(tab_th_info[i].lock));
			free_struct(threads, tab_th_info);
			fatal_perror("ft_nmap: init_threads: thread_create");
		}
	}
}

void	*scan_routine( void *arg )
{
	t_thread_arg	*th_info = (t_thread_arg *) arg;

	pthread_mutex_lock(&(th_info->lock));
	while (check_g_done() == 0)
	{
		while (check_g_done() == 0 && th_info->data_ready == 0)
		{
			pthread_cond_wait(&th_info->cond, &(th_info->lock));
		}
		th_info->data_ready = 0;
		
		if (check_g_done() == 1 && th_info->data_ready == 0)
			break ;
		pthread_mutex_lock(&g_print_lock);printf("(%d) Scanning %d ...\n", th_info->id, th_info->port.nb);pthread_mutex_unlock(&g_print_lock);
	}
	pthread_mutex_unlock(&(th_info->lock));
	return (NULL);
}

void threading_scan_port(t_info *info, t_host *host)
{
	(void) host;
	int last_port = info->first_port + info->port_range;
	int	port = info->first_port;
	t_thread_arg	*tab_th_info = NULL;
	pthread_t		*threads = NULL;
	alloc_values(&tab_th_info, &threads, info);

	init_threads(threads, tab_th_info, info);


	while (port < last_port)
	{
		for (uint8_t th_id = 0; port < last_port && th_id < info->nb_thread; th_id++)
		{
			if (pthread_mutex_trylock(&(tab_th_info[th_id].lock)) == 0)
			{
				if (tab_th_info[th_id].data_ready == 1)
				{
					pthread_mutex_unlock(&(tab_th_info[th_id].lock));
					continue ;
				}
				tab_th_info[th_id].port.nb = port;
				pthread_cond_signal(&tab_th_info[th_id].cond);
				tab_th_info[th_id].data_ready = 1;
				pthread_mutex_unlock(&(tab_th_info[th_id].lock));
				port++;
				usleep(1);
			}
		}
	}
	
	sleep(1);
	pthread_mutex_lock(&g_lock);
	g_done = 1;
	pthread_mutex_unlock(&g_lock);

	for (uint8_t th_id = 0; th_id < info->nb_thread; th_id++)
	{
		if (pthread_mutex_lock(&(tab_th_info[th_id].lock)) == 0)
		{
			if (tab_th_info[th_id].data_ready == 1)
			{
				pthread_mutex_unlock(&(tab_th_info[th_id].lock));
				continue ;
			}
			pthread_cond_signal(&tab_th_info[th_id].cond);
			pthread_mutex_unlock(&(tab_th_info[th_id].lock));
			usleep(1);
		}
	}

	close_threads(threads, tab_th_info, info->nb_thread);
}