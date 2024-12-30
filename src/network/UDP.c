#include "../../inc/nmap.h"

extern pthread_mutex_t	g_print_lock;

typedef struct	s_dns
{
	uint16_t	id;
	uint16_t	flags;
	uint16_t	question;
	uint16_t	ans_rrs;
	uint16_t	auth_rrs;
	uint16_t	add_rrs;
	uint8_t		seven;
	char		name[12];
	uint16_t	type;
	uint16_t	class;
}				t_dns;

void	craft_dns( char packet[4096] )
{
	t_dns	*data = (t_dns *)(packet + sizeof(struct iphdr) + sizeof(struct udphdr));

	data->id = 0x7777;	
	data->flags = htons(0x0100);
	data->question = htons(0x1);
	data->seven = 7;
	memcpy(data->name, "version.bind", 13);
	data->name[7] = 4;
	data->type = htons(0x10);
	data->class = htons(0x0003);
}

uint16_t init_udp_h( struct udphdr *udph, const uint16_t port_nb )
{
	uint16_t random_src_port = get_random_port();
	udph->source = htons(random_src_port);
	udph->dest = htons(port_nb);
	udph->len = htons(8 + UDP_PAYLOAD_SIZE);

	return (random_src_port);
}

void	init_values_udp( struct iphdr *iph, struct udphdr *udph, char packet[4096], struct pollfd *pollfd, const t_thread_arg *th_info, t_scan_port *port )
{
	char	filter_str[1024] = {0};

	srand(time(NULL));
	init_ip_h(iph, th_info, IPPROTO_UDP);
	iph->check = checksum((unsigned short *)packet, iph->tot_len);
	uint16_t random_src_port = init_udp_h(udph, port->nb);
	craft_dns(packet);
	udph->check = get_checksum(th_info, udph, IPPROTO_UDP);
	port->state[th_info->scan_type] = OPEN_FILT;
	
	pollfd->events = POLLIN;
	pollfd->fd = pcap_get_selectable_fd(th_info->handle);
	if (pollfd->fd == -1)
		fatal_perror("ft_nmap: pcap_get_selectable_fd");

	sprintf(filter_str, "src host %s and (udp or icmp) and src port %d and dst port %d", inet_ntoa(th_info->host->ping_addr.sin_addr), port->nb, random_src_port);
	setup_filter(filter_str, th_info->handle);
}

bool scan_udp( t_scan_port *port, t_thread_arg *th_info )
{
	char	packet[4096] = {0}; 
	struct iphdr *iph = (struct iphdr *)packet;
	struct udphdr *udph = (struct udphdr *)(packet + sizeof (struct iphdr));
	struct pollfd	pollfd = {0};


	init_values_udp(iph, udph, packet, &pollfd, th_info, port);

	if (send_recv_packet(port, th_info, pollfd, packet, iph) == 1)
		return (1);
	return (0);
}