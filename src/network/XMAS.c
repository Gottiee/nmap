#include "../../inc/nmap.h"

extern pthread_mutex_t	g_print_lock;

bool scan_xmas( t_scan_port *port, t_host *host, const uint8_t th_id )
{
	(void)port;
	(void)host;
	pthread_mutex_lock(&g_print_lock);printf("(%d) scan_xmas()\n", th_id);pthread_mutex_unlock(&g_print_lock);
	return (0);
}