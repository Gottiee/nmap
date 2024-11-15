#include "../inc/nmap.h"

pthread_mutex_t	g_lock;
pthread_mutex_t	g_print_lock;
bool	g_done = 0;
uint16_t	g_port = 0;
bool	data_ready = 0;
pthread_cond_t	g_cond;

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

	int	port_nb = 0;

	pthread_mutex_lock(&g_lock);
	while (data_ready == 0)
	{
		pthread_mutex_lock(&g_print_lock);
		printf("Thread waiting for data\n");
		pthread_mutex_unlock(&g_print_lock);
		pthread_cond_wait(&g_cond, &g_lock);
	}
	if (g_port != 0)
	{
		port_nb = g_port;
		data_ready = 0;
		g_port = 0;
	}
	pthread_mutex_unlock(&g_lock);
	pthread_mutex_lock(&g_print_lock);
	printf("Thread recevied data + g_lock unlocked\n");
	printf("Port number == %d\n", port_nb);
	pthread_mutex_unlock(&g_print_lock);

	return NULL;
}

void threading_scan_port(t_info *info, t_host *host)
{
	pthread_t *thread_id = NULL;

	// pthread_mutex_t mutex;
	int port_index = 0;
	// int thread_index = 0;
	// int nbr_of_port_scan = info->port_info->nbr_of_port_scan;
	// int current_nbr_of_thread = 0;

	pthread_mutex_init(&g_print_lock, NULL);


	// pthread_mutex_init(&mutex, NULL);
	thread_id = malloc(sizeof(pthread_t) * info->nb_thread);
	if (!thread_id)
		fatal_perror("Malloc error \"thread_id\"");
	pthread_mutex_lock(&g_print_lock);
	printf("%d bytes allocated\n", info->nb_thread);
	pthread_mutex_unlock(&g_print_lock);
	for (uint8_t i = 0; i < info->nb_thread; i++)
	{
		pthread_create(&thread_id[i], NULL, 
						&scan_routine, &host->port_tab[port_index]);
	}

	int	port = 0;
	while (g_done == 0)
	{
		if (port == 100)
			g_done = 1;
		if (port == 101)
		{
			pthread_mutex_lock(&g_print_lock);
			printf(">>> Quitting -> port == 101\n");
			pthread_mutex_unlock(&g_print_lock);
			return ;
		}
		pthread_mutex_lock(&g_lock);
		g_port = port;
		data_ready = 1;
		pthread_mutex_unlock(&g_lock);
		++port;
	}


	int	ret = 0;
	for (int i = 0; i < info->nb_thread; i++)
	{
		ret = pthread_join(thread_id[i], NULL);
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

	// while (port_index < nbr_of_port_scan)
	// {
	// 	thread_index = 0;
	// 	current_nbr_of_thread = 0;
	// 	while (thread_index < info->nb_thread && port_index < nbr_of_port_scan)
	// 	{
	// 		// printf("creation d'un thread index: %d, port index effectué: %d\n", thread_index, port_index);
	// 		host->port_tab[port_index].port_nbr = info->port_info->to_scan[port_index];
	// 		host->port_tab[port_index].type_scan = &info->scan_type;
	// 		pthread_create(&thread_id[thread_index], NULL, 
	// 						&scan_routine, &host->port_tab[port_index]);
	// 		thread_index++;
	// 		port_index++;
	// 		current_nbr_of_thread++;
	// 	}
	// 	for (int i = 0; i < current_nbr_of_thread; i++)
	// 		pthread_join(thread_id[i], NULL);
	// }
	// pthread_mutex_destroy(&mutex);
	pthread_mutex_destroy(&g_print_lock);
	free(thread_id);
	free(ports);
}