#ifndef NETWORK_H
#define NETWORK_H

#define OPEN 1
#define CLOSE 2
#define FILTERED 3
#include <stdbool.h>
#include <pcap.h>

typedef struct s_scan_port
{
	uint8_t	th_id;	//	JUSTE POUR LE DEBUG
	
	char	hostname[NI_MAXHOST];
	struct sockaddr_in	ping_addr;
	uint16_t nb;
	char *service;
	int state[7];
	int		sockfd;
	struct tcphdr	*tcp_h;
	bool	done;
} t_scan_port;

typedef struct	s_thread_arg
{
	//	THREAD
	uint8_t	id;
	uint	max_port;
	pthread_cond_t	cond;
	pthread_mutex_t	lock;

	//	SCAN
	t_scan_port	port;
	uint8_t	scan_type;	
}				t_thread_arg;


typedef struct s_info_port
{
	int nbr_of_port_scan;
	int to_scan[1024];
} t_info_port;

typedef struct s_host
{
	char	*name;
	t_scan_port port_tab[1024];
	struct s_host *next;
} t_host;

bool dns_lookup(char *input_domain, struct sockaddr_in *ping_addr);
bool fill_sockaddr_in(char *target, struct sockaddr_in *ping_addr);
void scan(struct sockaddr_in *ping_addr, t_info *info);

bool scan_all( uint8_t th_id );
bool scan_ack();
bool scan_fin();
bool scan_null();
bool scan_syn( t_scan_port *port );
bool scan_xmas();
bool scan_udp();
void setup_filter(char *filter_str, pcap_t *handle);
pcap_t *init_handler(char *device);
pcap_if_t *init_device();
#endif