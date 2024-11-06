#include "../inc/nmap.h"

void *scan_routine(void *port_struct)
{
    t_scan_port *port_scan = (t_scan_port *)port_struct;
    port_scan->state[0] = 1;
    printf("Thread: port scanned : %d\n", port_scan->port_nbr);
    return NULL;
}

void threading_scan_port(t_info *info, t_host *host)
{
    pthread_t *thread_id;
    // pthread_mutex_t mutex;
    int port_index = 0;
    int thread_index = 0;
    int nbr_of_port_scan = info->port_info->nbr_of_port_scan;
    int current_nbr_of_thread = 0;

    // pthread_mutex_init(&mutex, NULL);
    thread_id = malloc(sizeof(pthread_t) * nbr_of_port_scan);

    while (port_index < nbr_of_port_scan)
    {
        thread_index = 0;
        current_nbr_of_thread = 0;
        while (thread_index < info->nb_thread && port_index < nbr_of_port_scan)
        {
            // printf("creation d'un thread index: %d, port index effectué: %d\n", thread_index, port_index);
            host->port_tab[port_index].port_nbr = info->port_info->to_scan[port_index];
            pthread_create(&thread_id[thread_index], NULL, &scan_routine, &host->port_tab[port_index]);
            thread_index++;
            port_index++;
            current_nbr_of_thread++;
        }
        for (int i = 0; i < current_nbr_of_thread; i++)
            pthread_join(thread_id[i], NULL);
    }
    // pthread_mutex_destroy(&mutex);
    free(thread_id);
}