#ifndef NETWORK_H
#define NETWORK_H

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <poll.h>

#define NO_THREAD 0

#define OPEN 1
#define CLOSE 2
#define FILTERED 3
#define UNFILTERED 4
#define OPEN_FILT 5
#define CLOSE_FILT 6

#define UDP_PAYLOAD_SIZE 30

#include <stdbool.h>
#include <pcap.h>
#include <sys/syscall.h>

extern pthread_mutex_t g_print_lock;

typedef	struct	s_pseudo_hdr
{
	u_int32_t	source_address;
	u_int32_t	dest_address;
	u_int8_t	placeholder;
	u_int8_t	protocol;
	u_int16_t	tcp_length;
}				t_pseudo_hdr;

typedef struct s_scan_port
{	
	uint16_t nb;
	int state[6];
} t_scan_port;

typedef struct s_host
{
	char	*name;
	t_scan_port *port_tab;
	struct sockaddr_in	ping_addr;
	struct s_host *next;
	uint8_t open;
} t_host;

typedef struct	s_thread_arg
{
	//	THREAD
	bool	data_ready;
	bool	is_free;
	uint8_t	id;
	pthread_cond_t	cond;
	pthread_mutex_t	lock;

	//	SCAN
	uint8_t	scan_type;	
	uint16_t	index_port;
	int		sockfd;
	pcap_t	*handle;
	t_host *host;
	struct in_addr	ip_src;
}				t_thread_arg;

uint16_t get_random_port( void );
bool dns_lookup(char *input_domain, struct sockaddr_in *ping_addr);
void send_recv_packet( t_scan_port *port, t_thread_arg *th_info, struct pollfd pollfd, char packet[4096], struct iphdr *iph );
bool fill_sockaddr_in(char *target, struct sockaddr_in *ping_addr);
void scan(struct sockaddr_in *ping_addr, t_info *info, t_host *host);

void scan_switch( t_scan_port *port, t_thread_arg *th_info );
bool scan_all( t_scan_port *port, t_thread_arg th_info );


void scan_tcp( t_scan_port *port, t_thread_arg *th_info );
void scan_udp( t_scan_port *port, t_thread_arg *th_info );
void setup_filter(char *filter_str, pcap_t *handle);
pcap_t *init_handler( void );
pcap_if_t *init_device(t_info *info);
void	init_ip_h( struct iphdr *iph, const t_thread_arg *th_info, const uint8_t protocol );
uint16_t	get_checksum( const t_thread_arg *th_info, void *header, const uint8_t protocol );
//	ANALYSE PACKET

bool	handle_return_packet( const u_char *r_buf, t_scan_port *port, const uint8_t th_id, const uint8_t scan_type, t_host *host );

#endif