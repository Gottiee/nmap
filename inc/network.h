#ifndef NETWORK_H
#define NETWORK_H

#define OPEN 1
#define CLOSE 2
#define FILTERED 3
#include <stdbool.h>
#include <pcap.h>

typedef struct s_scan_port
{
	int port_nbr;
	char *service;
	int state[7];
	int *type_scan;
} t_scan_port;

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

typedef struct	s_thread
{
	bool	is_free;
	bool	data_ready;
	uint8_t	id;
	uint16_t	port_nb;
	pthread_cond_t	cond;
	pthread_mutex_t	lock;
}				t_thread;

bool dns_lookup(char *input_domain, struct sockaddr_in *ping_addr);
bool fill_sockaddr_in(char *target, struct sockaddr_in *ping_addr);
void scan(struct sockaddr_in *ping_addr, t_info *info);

void scan_ack();
void scan_fin();
void scan_null();
void scan_syn();
void scan_xmas();
void scan_udp();
void setup_filter(char *filter_str, pcap_t *handle);
pcap_t *init_handler(char *device);
pcap_if_t *init_device();
#endif