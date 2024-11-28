#ifndef NETWORK_H
#define NETWORK_H

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>

#define NO_THREAD 0

#define OPEN 1
#define CLOSE 2
#define FILTERED 3
#define OPEN_FILT 4
#include <stdbool.h>
#include <pcap.h>

typedef struct s_scan_port
{	
	uint16_t nb;
	char *service;
	int state; // open / filtered...
	int	sockfd;

	bool done;
} t_scan_port;

typedef struct s_host
{
	char	*name;
	t_scan_port *port_tab;
	struct s_host *next;
	struct sockaddr_in	ping_addr;
	int ip_src;
} t_host;

typedef struct	s_thread_arg
{
	//	THREAD
	uint8_t	id;
	// uint	max_port;
	pthread_cond_t	cond;
	pthread_mutex_t	lock;
	bool	data_ready;
	bool	is_free;

	//	SCAN
	uint8_t	scan_type;	
	uint16_t	index_port;
	int	sockfd;
	t_host *host;
}				t_thread_arg;

bool dns_lookup(char *input_domain, struct sockaddr_in *ping_addr);
bool fill_sockaddr_in(char *target, struct sockaddr_in *ping_addr);
void scan(t_info *info, t_host *current_host);

void scan_switch( t_scan_port *port, t_host *host, const uint8_t scan_type, const uint8_t th_id);
bool scan_all( t_scan_port *port, t_host *host, const uint8_t th_id );
bool scan_ack( t_scan_port *port, t_host host, const uint8_t th_id );
bool scan_fin( t_scan_port *port, t_host host, const uint8_t th_id );
bool scan_null( t_scan_port *port, t_host host, const uint8_t th_id );
bool scan_syn( t_scan_port *port, t_host host, const uint8_t th_id );
bool scan_xmas( t_scan_port *port, t_host host, const uint8_t th_id );
bool scan_udp( t_scan_port *port, t_host host, const uint8_t th_id );
void setup_filter(char *filter_str, pcap_t *handle);
pcap_t *init_handler(char *device);
pcap_if_t *init_device(t_info *info);

#endif