#ifndef THREAD_H
#define THREAD_H

#include <pthread.h>

typedef struct s_thread_scan
{
    int thread_it;
    pcap_t *handle;
} t_thread_scan;

void threading_scan_port(t_info *info, t_host *host);
pcap_t **get_handle();
#endif