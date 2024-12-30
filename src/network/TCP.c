#include "../../inc/nmap.h"

extern pthread_mutex_t	g_print_lock;

void	print_packet( const uint8_t th_id, struct tcphdr *r_tcp, const char *r_dest_addr, const char *r_src_addr )
{
	pthread_mutex_lock(&g_print_lock);
	printf("(%d)---------------------------------\n", th_id);
	printf("saddr == %s \ndaddr == %s\nseq == %u\nack_seq == %u\n",
			r_src_addr, r_dest_addr, ntohl(r_tcp->seq), ntohl(r_tcp->ack_seq));
	printf("source == %hu\ndest == %hu\nr_tcp->syn = %hu\nack = %hu\npsh = %hu\n",
			ntohs(r_tcp->source), ntohs(r_tcp->dest), ntohs(r_tcp->syn), r_tcp->ack, r_tcp->psh);
	printf("r_tcp->src_addr = %hu\n",
			ntohs(r_tcp->dest));
	printf("\n");
	pthread_mutex_unlock(&g_print_lock);
}

uint16_t	init_tcp_h( struct tcphdr *tcph, const uint16_t port_nb, const uint8_t scan_type )
{
	uint16_t random_src_port = get_random_port();
	tcph->source = htons(random_src_port);
	tcph->dest = htons(port_nb);
	tcph->doff = 5;
	switch (scan_type)
	{
		case SYN:
			tcph->syn = 1;
			break ;
		case ACK:
			tcph->ack = 1;
			break ;
		case FIN:
			tcph->fin = 1;		
			break ;
		case XMAS:
			tcph->fin = 1;
			tcph->psh = 1;
			tcph->urg = 1;		
			break ;
		default:
			break ;
	}
	tcph->window = htons(5840);
	return random_src_port;
}

bool	init_values_tcp( struct iphdr *iph, struct tcphdr *tcph, char packet[4096], struct pollfd *pollfd, const t_thread_arg *th_info, t_scan_port *port )
{
	char	filter_str[1024] = {0};

	srand(time(NULL));
	init_ip_h(iph, th_info, IPPROTO_TCP);
	iph->check = checksum((unsigned short *)packet, iph->tot_len);
	uint16_t random_src_port =  init_tcp_h(tcph, port->nb, th_info->scan_type);
	tcph->check = get_checksum(th_info, tcph, IPPROTO_TCP);
	if (th_info->scan_type == S_NULL || th_info->scan_type == FIN || th_info->scan_type == XMAS)
		port->state[th_info->scan_type] = UNFILTERED;
	else
		port->state[th_info->scan_type] = FILTERED;
	
	pollfd->events = POLLIN;
	pollfd->fd = pcap_get_selectable_fd(th_info->handle);
	if (pollfd->fd == -1)
		fatal_perror("ft_nmap: pcap_get_selectable_fd");

	sprintf(filter_str, "src host %s and (tcp or icmp) and src port %d and dst port %d", inet_ntoa(th_info->host->ping_addr.sin_addr), port->nb, random_src_port);
	if (setup_filter(filter_str, th_info->handle) == 1)
		return (1);
	return (0);
}

bool scan_tcp( t_scan_port *port, t_thread_arg *th_info )
{
	struct pollfd	pollfd = {0};
	char packet[4096] = {0};
	struct iphdr *iph = (struct iphdr *) packet;
	struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct iphdr));
	
	if (init_values_tcp(iph, tcph, packet, &pollfd, th_info, port) == 1)
		return (1);

	if (send_recv_packet(port, th_info, pollfd, packet, iph) == 1)
		return (1);
	return (0);
}
