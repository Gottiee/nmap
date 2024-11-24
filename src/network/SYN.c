#include "../../inc/nmap.h"

extern pthread_mutex_t	g_print_lock;

void	init_tcp_h( struct tcphdr *tcp_h, uint16_t *dst_port )
{
	bzero(tcp_h, sizeof(struct tcphdr));
	tcp_h->dest = htons(*dst_port);
	tcp_h->source = htons(80);
	// tcp_h->seq = htonl((uint32_t)rand());
	tcp_h->seq = htonl(1000);
	// tcp_h->ack_seq = htonl(2);
	tcp_h->res1 = htons(4);
	tcp_h->doff = htons(5);
	tcp_h->syn = htons(1);
	tcp_h->th_win = htons(1024);
	tcp_h->th_sum = 0;
	tcp_h->th_urp = 0;
}

void	get_own_ip( void )
{
	
}

void	init_ip_h( struct iphdr *ip_hdr, uint16_t *dst_port )
{
	ip_hdr->ihl = sizeof(struct iphdr);
	ip_hdr->version = 4;
	ip_hdr->tos = 0;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	ip_hdr->id = htons(getpid());
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = IPDEFTTL;
	ip_hdr->protocol = IPPROTO_TCP;
	ip_hdr->check = 0;		//	A DEFINIR AVEC CHECKSUM()
	ip_hdr->saddr = htonl();
	ip_hdr->;
	ip_hdr->;
}

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

bool	check_packet( const struct tcphdr *s_tcp, const struct tcphdr *r_tcp, const uint16_t th_id )
{
	pthread_mutex_lock(&g_print_lock);
	if (ntohs(r_tcp->dest) != ntohs(s_tcp->source))
		printf("(%d) Unvalid destination port (r: %d != s: %d)\n", th_id, ntohs(r_tcp->dest), ntohs(s_tcp->source));
	if (ntohs(r_tcp->syn) && ntohs(r_tcp->ack))
		printf("(%d) Valid SYN/ACK packet\n", th_id);
	if (ntohs(r_tcp->syn) && ntohs(r_tcp->psh))
		printf("(%d) Valid SYN/PSH packet\n", th_id);
	if (ntohl(r_tcp->ack_seq) != 1001)
		printf("(%d) Unvalid ack sequence in the packet (r: %d != s: %d)\n", th_id, ntohl(r_tcp->ack_seq), 1001);
	
	pthread_mutex_unlock(&g_print_lock);
	return (0);
}

bool	handle_return_packet( char *r_buf, t_scan_port *port_info )
{
	struct iphdr	*r_ip = (struct iphdr *)r_buf;
	struct tcphdr	*r_tcp = (struct tcphdr *)(r_buf + (r_ip->ihl * 4));
	(void) r_ip; (void) r_tcp;
	char	buf_ip[2][INET_ADDRSTRLEN] = {0};	//	[0]: DEST, [1]: SRC
	inet_ntop(AF_INET, &r_ip->daddr, buf_ip[0], INET6_ADDRSTRLEN);
	inet_ntop(AF_INET, &port_info->ping_addr.sin_addr.s_addr, buf_ip[1], INET6_ADDRSTRLEN);

	print_packet(port_info->th_id, r_tcp, buf_ip[0], buf_ip[1]);
	if (strcmp(buf_ip[0], buf_ip[1]) != 0)
		printf("Unvalid Destination addr (r: %s != s: %s\n", buf_ip[0], buf_ip[1]);
	if (check_packet(port_info->ip_h, r_tcp, port_info->th_id) == 1)
		return (1);
	return (0);
}

bool scan_syn( t_scan_port *port_info )
{
	printf("(%d) >>> scan_syn(): port_nb = %d | ping_addr == %s, \n", 
				port_info->th_id, port_info->nb, inet_ntoa(port_info->ping_addr.sin_addr));
	char	r_buf[IP_MAXPACKET] = {0};

	init_ip_h(port_info->ip_h, &(port_info->nb));
	port_info->ip_h->check = checksum(port_info->ip_h, sizeof(struct tcphdr));
	
	if (sendto(port_info->sockfd, port_info->ip_h, sizeof(struct tcphdr), 0, (struct sockaddr *)&(port_info->ping_addr),sizeof(struct sockaddr)) == -1)
		return (return_error("ft_nmap: syn: send_syn(): sendto()"));
	pthread_mutex_lock(&g_print_lock);
	printf("(%d) > sendto(): OK\n", port_info->th_id);
	pthread_mutex_unlock(&g_print_lock);

	bzero(r_buf, IP_MAXPACKET);
	if (recvfrom(port_info->sockfd, r_buf, 1024, 0 , NULL, NULL) == -1)
		return (return_error("ft_nmap: syn: send_syn(): recvfrom()"));	
	pthread_mutex_lock(&g_print_lock);
	printf("(%d) > recvfrom(): OK\n", port_info->th_id);
	pthread_mutex_unlock(&g_print_lock);

	handle_return_packet(r_buf, port_info);

	return (0);
}