#ifndef THREAD_H
#define THREAD_H

#include <pthread.h>

void threading_scan_port(t_info *info, t_host *host);
void	close_all_threads( pthread_t *threads, t_thread_arg *tab_th_info, const uint8_t nb_th );

#endif