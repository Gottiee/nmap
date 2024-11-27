#include "../../inc/nmap.h"

extern pthread_mutex_t	g_print_lock;

bool scan_udp( t_scan_port *port, t_host host, const uint8_t th_id )
{
	(void) port;
	(void) th_id;
	(void) host;
	port->state = OPEN;
	// printf("port %d state = open\n", port->nb);
	// pthread_mutex_lock(&g_print_lock);printf("(%d) scan_udp()\n", th_id);pthread_mutex_unlock(&g_print_lock);
	return (0);
}