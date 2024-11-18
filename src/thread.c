#include "../inc/nmap.h"

pthread_mutex_t	g_print_lock;
pthread_mutex_t	g_lock;
bool	g_done = 0;

void	init_ths_struct( t_thread *ths_struct, const uint8_t size )
{
	for (uint8_t i = 0; i < size; i++)
	{
		ths_struct->is_free = 1;
		ths_struct->id = i;
		if (pthread_mutex_init(&ths_struct->lock, NULL) != 0)
			printf("thread init failed\n");
		if (pthread_cond_init(&ths_struct->cond, NULL) != 0)
			printf("cond init failed\n");
		ths_struct++;
	}
}

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

	pthread_mutex_lock(&th_struct->lock);
	while (1)
	{
		pthread_mutex_lock(&g_lock);
		if (g_done == 1)
			break ;
		pthread_mutex_unlock(&g_lock);
		while (th_struct->data_ready == 0)
			pthread_cond_wait(&th_struct->cond, &th_struct->lock);
		th_struct->data_ready = 0;
		pthread_mutex_lock(&g_print_lock);
		printf("(%d) port number == %d\n", th_struct->id, th_struct->port_nb);
		pthread_mutex_unlock(&g_print_lock);
	}
	pthread_mutex_unlock(&th_struct->lock);
	return NULL;
}

void threading_scan_port(t_info *info, t_host *host)
{
	(void) host;
	pthread_t *threads = NULL;
	t_thread	*ths_struct = malloc(sizeof(t_thread) * info->nb_thread);
	if (ths_struct == NULL)
		fatal_perror("Malloc error \"thread_id\"");
	init_ths_struct(ths_struct, info->nb_thread);

	pthread_mutex_init(&g_print_lock, NULL);
	pthread_mutex_init(&g_lock, NULL);

	// pthread_mutex_init(&mutex, NULL);
	threads = malloc(sizeof(pthread_t) * info->nb_thread);
	if (!threads)
		fatal_perror("Malloc error \"thread_id\"");
	printf("%d bytes allocated\n", info->nb_thread);
	for (uint8_t i = 0; i < info->nb_thread; i++)
	{
		pthread_create(&threads[i], NULL, 
						&scan_routine, &(ths_struct[i]));
		printf("thread_create(%d)\n", i);
	}

	sleep(2);

	int	port = 0;
	//	BOUCLE PRINCIPALE
	while (port < 50)
	{
		//	BOUCLE TOUS LES THREADS
		for (uint8_t th_id = 0; th_id < info->nb_thread; th_id++)
		{
			//	CHECK IF MUTEX UNLOCK WITHOUT BLOCKING
			if (pthread_mutex_trylock(&(ths_struct[th_id].lock)) == 0)
			{
				pthread_mutex_lock(&g_print_lock);
				printf("Main > (%d) mutex locked: port == %d\n", th_id, port);
				pthread_mutex_unlock(&g_print_lock);
				ths_struct[th_id].port_nb = port;
				ths_struct[th_id].data_ready = 1;
				pthread_cond_signal(&(ths_struct[th_id].cond));
				pthread_mutex_unlock(&(ths_struct[th_id].lock));
				++port;
				usleep(20);
			}
		}
	}
	
	pthread_mutex_lock(&g_lock);
	g_done = 1;
	pthread_mutex_unlock(&g_lock);

	pthread_mutex_lock(&g_print_lock);
	printf("Infinite loop finished\n");
	pthread_mutex_unlock(&g_print_lock);

	int	ret = 0;
	for (int i = 0; i < info->nb_thread; i++)
	{
		ret = pthread_join(threads[i], NULL);
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
			exit(1);
		}
	}
	pthread_mutex_destroy(&g_print_lock);
	pthread_mutex_destroy(&g_lock);
	free(threads);
	printf("Leaving\n");
	// free(ports);
}