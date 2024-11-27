#include "../../inc/nmap.h"

extern pthread_mutex_t	g_print_lock;

// void	init_tcp_h( struct tcphdr *tcp_h, uint16_t *dst_port )
// {
// 	bzero(tcp_h, sizeof(struct tcphdr));
// 	tcp_h->dest = htons(*dst_port);
// 	tcp_h->source = htons(80);
// 	// tcp_h->seq = htonl((uint32_t)rand());
// 	tcp_h->seq = htonl(1000);
// 	// tcp_h->ack_seq = htonl(2);
// 	tcp_h->res1 = htons(4);
// 	tcp_h->doff = htons(5);
// 	tcp_h->syn = htons(1);
// 	tcp_h->th_win = htons(1024);
// 	tcp_h->th_sum = 0;
// 	tcp_h->th_urp = 0;
// }

// void	get_own_ip( void )
// {
	
// }

// void	print_packet( const uint8_t th_id, struct tcphdr *r_tcp, const char *r_dest_addr, const char *r_src_addr )
// {
// 	pthread_mutex_lock(&g_print_lock);
// 	printf("(%d)---------------------------------\n", th_id);
// 	printf("saddr == %s \ndaddr == %s\nseq == %u\nack_seq == %u\n",
// 			r_src_addr, r_dest_addr, ntohl(r_tcp->seq), ntohl(r_tcp->ack_seq));
// 	printf("source == %hu\ndest == %hu\nr_tcp->syn = %hu\nack = %hu\npsh = %hu\n",
// 			ntohs(r_tcp->source), ntohs(r_tcp->dest), ntohs(r_tcp->syn), r_tcp->ack, r_tcp->psh);
// 	printf("r_tcp->src_addr = %hu\n",
// 			ntohs(r_tcp->dest));
// 	printf("\n");
// 	pthread_mutex_unlock(&g_print_lock);
// }

// bool	check_packet( const struct tcphdr *s_tcp, const struct tcphdr *r_tcp, const uint16_t th_id )
// {
// 	pthread_mutex_lock(&g_print_lock);
// 	if (ntohs(r_tcp->dest) != ntohs(s_tcp->source))
// 		printf("(%d) Unvalid destination port (r: %d != s: %d)\n", th_id, ntohs(r_tcp->dest), ntohs(s_tcp->source));
// 	if (ntohs(r_tcp->syn) && ntohs(r_tcp->ack))
// 		printf("(%d) Valid SYN/ACK packet\n", th_id);
// 	if (ntohs(r_tcp->syn) && ntohs(r_tcp->psh))
// 		printf("(%d) Valid SYN/PSH packet\n", th_id);
// 	if (ntohl(r_tcp->ack_seq) != 1001)
// 		printf("(%d) Unvalid ack sequence in the packet (r: %d != s: %d)\n", th_id, ntohl(r_tcp->ack_seq), 1001);	
// 	pthread_mutex_unlock(&g_print_lock);
// 	return (0);
// }

bool	handle_return_packet( char *r_buf, t_scan_port *port, const uint8_t th_id )
{
	struct iphdr	*r_ip = (struct iphdr *)r_buf;
	struct tcphdr	*r_tcp = (struct tcphdr *)(r_buf + (r_ip->ihl * 4));
	(void) r_ip; (void) r_tcp; (void) port;

	if (r_tcp->syn && r_tcp->ack)
	{
		pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn(): recv SYN/ACK\n", th_id);pthread_mutex_unlock(&g_print_lock);
		//	STATE = OPEN
	}
	else if (r_tcp->rst)
	{
		pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn(): recv RST\n", th_id);pthread_mutex_unlock(&g_print_lock);
		//	STATE = CLOSED
	}
	
	return (0);
}

void	init_ip_h( struct iphdr *ip_h, const uint32_t dest_addr )
{
	ip_h->ihl = sizeof(struct iphdr) / 4;
	ip_h->version = 4;
	ip_h->tos = 0;
	ip_h->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	ip_h->id = htons(getpid());
	ip_h->frag_off = 0;
	ip_h->ttl = IPDEFTTL;
	ip_h->protocol = IPPROTO_TCP;
	ip_h->check = 0;		//	A DEFINIR AVEC CHECKSUM()
	ip_h->saddr = inet_addr("10.0.2.15");
	ip_h->daddr = htonl(dest_addr);
	ip_h->check = checksum(&ip_h, sizeof(struct tcphdr));
}

void	init_tcp_h( struct tcphdr *tcp_h, const t_scan_port *port )
{
	srand(time(NULL));

	tcp_h->source = htons(7777);
	tcp_h->dest = port->nb;
	tcp_h->seq = rand();
	tcp_h->ack_seq = 0;
	tcp_h->syn = 1;
	tcp_h->res1 = 0;
	tcp_h->res2 = 0;
	tcp_h->window = htons(1024);
	tcp_h->urg_ptr = 0;
	tcp_h->check = checksum(&tcp_h, sizeof(struct tcphdr));
}

bool scan_syn( t_scan_port *port, t_host host, const uint8_t th_id )
{
	pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn(): port_nb = %d | ping_addr == %s\n", th_id, port->nb, inet_ntoa(host.ping_addr.sin_addr));pthread_mutex_unlock(&g_print_lock);
	uint8_t	retry = 0;
	char	s_buf[IP_MAXPACKET] = {0};
	char	r_buf[IP_MAXPACKET] = {0};
	struct iphdr	ip_h;
	struct tcphdr	tcp_h;

	init_ip_h(&ip_h, host.ping_addr.sin_addr.s_addr);
	bzero(&tcp_h, sizeof(struct tcphdr));
	init_tcp_h(&tcp_h, port);
	memcpy(s_buf, &ip_h, sizeof(struct iphdr));
	memcpy(s_buf + sizeof(struct iphdr), &tcp_h, sizeof(struct tcphdr));
	for (unsigned int i = sizeof(struct iphdr) + sizeof(struct tcphdr); i < IP_MAXPACKET; i++)
	{
		s_buf[i] = '0';
	}
	
	for (; retry < 2; retry++)
	{
		if (sendto(port->sockfd, &ip_h, sizeof(struct tcphdr), 0, (struct sockaddr *)&(host.ping_addr),sizeof(struct sockaddr)) == -1)
			return (return_error("ft_nmap: syn: send_syn(): sendto()"));
		pthread_mutex_lock(&g_print_lock);printf("(%d) > sendto(): OK\n", th_id);pthread_mutex_unlock(&g_print_lock);

		bzero(r_buf, IP_MAXPACKET);
		if (recvfrom(port->sockfd, r_buf, 1024, 0 , NULL, NULL) == -1)
		{
			if (errno == ETIMEDOUT)
			{
			pthread_mutex_lock(&g_print_lock);printf("(%d) > recvfrom(): Timeout\n", th_id);pthread_mutex_unlock(&g_print_lock);
				
				continue ;
			}
			else
				return (return_error("ft_nmap: syn: send_syn(): recvfrom()"));	
		}
		else
		{
			pthread_mutex_lock(&g_print_lock);printf("(%d) > recvfrom(): OK\n", th_id);pthread_mutex_unlock(&g_print_lock);
			break ;
		}
	}


	handle_return_packet(r_buf, port, th_id);

	return (0);
}