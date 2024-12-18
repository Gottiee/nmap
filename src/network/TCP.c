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

uint16_t	get_checksum( const t_thread_arg *th_info, const struct tcphdr *tcp_h )
{
	t_pseudo_hdr	psh = {0};
	char	pseudogram[sizeof(t_pseudo_hdr) + sizeof(struct tcphdr)] = {0};

	psh.source_address = th_info->ip_src.s_addr;  // Adresse source
	psh.dest_address = th_info->host->ping_addr.sin_addr.s_addr;  // Adresse de destination
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));

	memcpy(pseudogram, (char *)&psh, sizeof(t_pseudo_hdr));
	memcpy(pseudogram + sizeof(t_pseudo_hdr), tcp_h, sizeof(struct tcphdr));
	return(checksum((unsigned short *)pseudogram, sizeof(t_pseudo_hdr) + sizeof(struct tcphdr)));
}

void	init_ip_h( struct iphdr *iph, const t_thread_arg *th_info )
{
	iph->ihl = 5;
	iph->version = IPVERSION;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	iph->id = htonl(syscall(SYS_gettid));
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->saddr = th_info->ip_src.s_addr;
	iph->daddr = th_info->host->ping_addr.sin_addr.s_addr;
}

void	init_tcp_h( struct tcphdr *tcph, const uint16_t port_nb, const uint8_t scan_type )
{
	tcph->source = htons(get_random_port());
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
}

void	init_values_tcp( struct iphdr *iph, struct tcphdr *tcph, char packet[4096], struct pollfd *pollfd, const t_thread_arg *th_info, t_scan_port *port )
{
	char	filter_str[1024] = {0};

	srand(time(NULL));
	init_ip_h(iph, th_info);
	iph->check = checksum((unsigned short *)packet, iph->tot_len);
	init_tcp_h(tcph, port->nb, th_info->scan_type);
	tcph->check = get_checksum(th_info, tcph);
	if (th_info->scan_type == S_NULL || th_info->scan_type == FIN || th_info->scan_type == XMAS)
		port->state[th_info->scan_type] = UNFILTERED;
	else
		port->state[th_info->scan_type] = FILTERED;
	
	pollfd->events = POLLIN;
	pollfd->fd = pcap_get_selectable_fd(th_info->handle);
	if (pollfd->fd == -1)
		fatal_perror("ft_nmap: pcap_get_selectable_fd");

	// sprintf(filter_str, "src host %s and (tcp or icmp)", inet_ntoa(th_info->host.ping_addr.sin_addr));
	sprintf(filter_str, "src host %s and (tcp or icmp) and src port %d", inet_ntoa(th_info->host->ping_addr.sin_addr), port->nb);
	setup_filter(filter_str, th_info->handle);

}

bool scan_tcp( t_scan_port *port, t_thread_arg *th_info )
{
	// pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn(): port_nb(%p) = %d | ping_addr == %s\n", th_info->id, &(port->nb), port->nb, inet_ntoa(th_info->host.ping_addr.sin_addr));pthread_mutex_unlock(&g_print_lock);

	pthread_mutex_lock(&g_print_lock);printf( BG_BLUE "(%d) >>> SCANNING %d\n" RESET, th_info->id, th_info->scan_type);pthread_mutex_unlock(&g_print_lock);
	uint8_t	retry = 0;
	const u_char	*r_data = NULL;
	int		ret_val = 0;
	struct pcap_pkthdr	*pkt_h = NULL;
	struct pollfd	pollfd = {0};
	char packet[4096] = {0};
	struct iphdr *iph = (struct iphdr *) packet;
	struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct iphdr));
	
	init_values_tcp(iph, tcph, packet, &pollfd, th_info, port);

	for (; retry < 2; retry++)
	{
		if (sendto(th_info->sockfd, packet, iph->tot_len, 0, 
			(struct sockaddr *)&(th_info->host->ping_addr), sizeof(struct sockaddr)) == -1)
			return (return_error("ft_nmap: syn: sendto(): sendto()"));

	arm_poll:
		ret_val = poll(&pollfd, 1, 400);
		if (ret_val == -1)
			fatal_perror("ft_nmap: poll");
		else if (ret_val == 0)
		{
			printf(RED "(%d)>>> poll(%d) TO\n" RESET, th_info->id, port->nb);
			continue ;
		}
		else if (ret_val >= 0 && pollfd.revents & POLLIN)
		{
			ret_val = pcap_next_ex(th_info->handle, &pkt_h, &r_data);
			if (ret_val == 1)
			{
				pthread_mutex_lock(&g_print_lock);printf( GREEN "(%d) > pcap_next(%d): received\n " RESET, th_info->id, port->nb);pthread_mutex_unlock(&g_print_lock);
				handle_return_packet(r_data, port, th_info->id, th_info->scan_type, th_info->host);
				break ;
			}
			else if (ret_val == 0)
			{
				printf("(%d) >>> pcap_next(%d): timed out\n", th_info->id, port->nb);
				goto arm_poll;
			}
			else 
			{
				fprintf(stderr, "ft_nmap: pcap_next_ex: %s\n", pcap_geterr(th_info->handle));
				return (1);
			}
		}
		else
		{
			pthread_mutex_lock(&g_print_lock);printf("(%d) ret_val == %d\n", th_info->id, ret_val);pthread_mutex_unlock(&g_print_lock);
		}
	}
	return (0);
}
