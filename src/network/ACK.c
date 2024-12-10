#include "../../inc/nmap.h"

extern	pthread_mutex_t	g_print_lock;

bool scan_ack( t_scan_port *port, const t_thread_arg *th_info )
{
	(void)port;
	(void)th_info;
	pthread_mutex_lock(&g_print_lock);printf("(%d) scan_ack1	()\n", th_info->id);pthread_mutex_unlock(&g_print_lock);
	return (0);
}