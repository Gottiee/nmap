#include "../inc/nmap.h"

pthread_mutex_t	g_print_lock;
pthread_mutex_t	g_lock;
bool	g_done = 0;

void *scan_routine(void *port_struct)
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
	t_thread	*th_struct = (t_thread *)port_struct;
	int		wait_ret = 0;
	struct timespec	wait_time;
	
	pthread_mutex_lock(&th_struct->lock);
	while (1)
	{
		pthread_mutex_lock(&g_lock);
		if (g_done == 1)
		{
			pthread_mutex_unlock(&g_lock);
			break ;
		}
		pthread_mutex_unlock(&g_lock);
		gettimeofday((struct timeval *)&wait_time, NULL);
		wait_time.tv_sec += 1;
		while (th_struct->data_ready == 0 && wait_ret != ETIMEDOUT)
		{
			pthread_mutex_lock(&g_lock);
			if (g_done == 1)
			{
				pthread_mutex_unlock(&g_lock);
				break ;
			}
			pthread_mutex_unlock(&g_lock);
			wait_ret = pthread_cond_timedwait(&th_struct->cond, &th_struct->lock, &wait_time);
			if (wait_ret == ETIMEDOUT)
			{
				pthread_mutex_lock(&g_print_lock);
				printf("(%d) wait timed out\n", th_struct->id);
				pthread_mutex_unlock(&g_print_lock);
				break ;
			}
		}
		if (wait_ret == ETIMEDOUT)
			break ;
		th_struct->data_ready = 0;
		pthread_mutex_lock(&g_print_lock);
		printf("(%d) port number == %d\n", th_struct->id, th_struct->port_nb);
		pthread_mutex_unlock(&g_print_lock);
	}
	pthread_mutex_lock(&g_print_lock);
	pthread_mutex_unlock(&th_struct->lock);
	printf("(%d) end routine\n", th_struct->id);
	pthread_mutex_unlock(&g_print_lock);
	return NULL;
}

bool	child_thread_main( pthread_t **threads, t_thread **ths_struct, const t_info *info )
{
	*ths_struct = malloc(sizeof(t_thread) * info->nb_thread);
	if (*ths_struct == NULL)
	{
		fprintf(stderr, "Malloc error \"thread_id\"");
		return (1);
	}
	// printf("malloc struct addr = %p\n", *ths_struct);

	// pthread_mutex_init(&mutex, NULL);
	(*threads) = malloc(sizeof(pthread_t) * info->nb_thread);
	if ((*threads) == NULL)
	{
		fprintf(stderr, "Malloc error \"thread_id\"");
		return (1);
	}
	// printf("%d bytes allocated\n", info->nb_thread);

	pthread_mutex_init(&g_print_lock, NULL);
	pthread_mutex_init(&g_lock, NULL);
	for (uint8_t i = 0; i < info->nb_thread; i++)
	{
		(*ths_struct)[i].is_free = 1;
		(*ths_struct)[i].id = i;
		(*ths_struct)[i].data_ready = 0;
		if (pthread_mutex_init(&((*ths_struct)[i].lock), NULL) != 0)
			printf("thread init failed\n");
		if (pthread_cond_init(&((*ths_struct)[i].cond), NULL) != 0)
			printf("cond init failed\n");
		
		// printf("thread_main > struct[%d] addr = %p\n", i, &(*ths_struct)[i]);
		if (pthread_create(&((*threads)[i]), NULL, &scan_routine, &((*ths_struct)[i])) != 0)
		{
			fprintf(stderr, "pthread_create failed\n");
			return (1);
		}
		pthread_mutex_lock(&g_print_lock);
		printf("thread_create(%d)\n", i);
		pthread_mutex_unlock(&g_print_lock);
	}
	return (0);
}

bool	closing_threading_ressources( pthread_t **threads, t_thread **ths_struct, t_info *info )
{
	int	ret = 0;
	for (int i = 0; i < info->nb_thread; i++)
	{
		pthread_mutex_lock(&g_print_lock);
		printf("(%d) joining ... \n", i);
		pthread_mutex_unlock(&g_print_lock);
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
		pthread_cond_destroy(&((*ths_struct)[i].cond));
		pthread_mutex_destroy(&((*ths_struct)[i].lock));
		pthread_mutex_lock(&g_print_lock);
		printf("(%d) joined\n", i);
		pthread_mutex_unlock(&g_print_lock);
	}
	free(*threads);
	free(*ths_struct);
	return (0);
}

void threading_scan_port(t_info *info, t_host *host)
{
	(void) host;
	pthread_t	*threads = NULL;
	t_thread	*ths_struct = NULL;

	if (child_thread_main(&threads, &ths_struct, info) == 1)
	{
		fprintf(stderr, "init_value() failed\n");
		return ;
	}
	// sleep(2);
	// printf("main > struct addr = %p\n", ths_struct);

	int	port = 0;
	//	BOUCLE PRINCIPALE
	while (port < 1024)
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
				ths_struct[th_id].port_nb = port;
				ths_struct[th_id].data_ready = 1;
				pthread_cond_signal(&(ths_struct[th_id].cond));
				pthread_mutex_unlock(&(ths_struct[th_id].lock));
				if (++port >= 1024)
					break ;
				usleep(1);
			}
		}
	}
	
	pthread_mutex_lock(&g_lock);
	g_done = 1;
	pthread_mutex_unlock(&g_lock);

	pthread_mutex_lock(&g_print_lock);
	printf("Infinite loop finished\n");
	pthread_mutex_unlock(&g_print_lock);

	if (closing_threading_ressources(&threads, &ths_struct, info) == 1)
	{
		fprintf(stderr, "closing ressources failed\n");
	}

	pthread_mutex_destroy(&g_print_lock);
	pthread_mutex_destroy(&g_lock);
	printf("Leaving\n");
	// free(ports);
}