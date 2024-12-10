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


bool	handle_return_packet( const u_char *r_buf, t_scan_port *port, const uint8_t th_id )
{
	struct iphdr	*r_ip = (struct iphdr *)r_buf;
	struct tcphdr	*r_tcp = (struct tcphdr *)(r_buf + (r_ip->ihl * 4));
	struct icmphdr	*r_icmp = (struct icmphdr *)(r_buf + (r_ip->ihl * 4));
	struct in_addr	s_addr;
	s_addr.s_addr = r_ip->saddr;
	(void) r_ip; (void) r_tcp; (void) port;
	if (r_ip->protocol == IPPROTO_ICMP)
	{
		//	ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
		if (r_icmp->type == 3)
		{
			if (r_icmp->code == 1 || r_icmp->code == 2 || r_icmp->code == 3 
				|| r_icmp->code == 9 || r_icmp->code == 10 || r_icmp->code == 13)
			{
				//	STATE = FILTERED
				pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn: handle return: icmp code %d type %d received\n", th_id, r_icmp->type, r_icmp->code);pthread_mutex_unlock(&g_print_lock);
			}
		}
		else
		{
			pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn: handle return: icmp type %d received => error\n", th_id, r_icmp->type);pthread_mutex_unlock(&g_print_lock);
			return (1);
		}
	}
	else if (r_ip->protocol == IPPROTO_TCP)
	{
		pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn(): recv TCP ", th_id);pthread_mutex_unlock(&g_print_lock);
		if (r_tcp->syn)
		{
			pthread_mutex_lock(&g_print_lock);printf("(%d)flag SYN ", th_id);pthread_mutex_unlock(&g_print_lock);
			//	STATE = OPEN
		}
		if (r_tcp->ack)
		{
			pthread_mutex_lock(&g_print_lock);printf("(%d)flag ACK ", th_id);pthread_mutex_unlock(&g_print_lock);
		}
		if (r_tcp->rst)
		{
			pthread_mutex_lock(&g_print_lock);printf("(%d)flag RST ", th_id);pthread_mutex_unlock(&g_print_lock);
			//	STATE = CLOSED
		}
	}
	else
	{
		pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn(): recv protocol %d\n", th_id, r_ip->protocol);pthread_mutex_unlock(&g_print_lock);
		//	STATE = CLOSED
	}
	pthread_mutex_lock(&g_print_lock);printf("(%s)\n", inet_ntoa(s_addr));pthread_mutex_unlock(&g_print_lock);
	return (0);
}

void	tests_r_packet( const char r_buf[IP_MAXPACKET], const uint8_t th_id )
{
	const struct iphdr	*ip_h = (const struct iphdr *) r_buf;
	const struct tcphdr	*tcp_h = NULL;
	const struct icmphdr	*icmp_h = NULL;

	if (ip_h->protocol == IPPROTO_TCP)
	{
		// TCP SYN/ACK response => open
		// TCP RST response	=> closed
		tcp_h = (const struct tcphdr *) (r_buf + sizeof(struct iphdr));
		if ((tcp_h->syn != 1 || tcp_h->ack != 1) && tcp_h->rst != 1)
			printf(RED "(%d) tcp wrong flags\n" RESET, th_id);
		else
			printf(GREEN "(%d) tcmp packet OK\n" RESET, th_id);
	}
	else if (ip_h->protocol == IPPROTO_ICMP)
	{
		// ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13) => filtered
		icmp_h = (const struct icmphdr *) (r_buf + sizeof(struct iphdr));
		if (icmp_h->type != 3)
			printf(RED "(%d) icmp wrong type (Received: %d\n" RESET, th_id, icmp_h->type);
		else if (icmp_h->code != 1 && icmp_h->code != 2 && icmp_h->code != 3 && icmp_h->code != 9 && 
				icmp_h->code != 10 && icmp_h->code != 13)
			printf(RED "(%d) icmp wrong code (Received: %d)\n" RESET, th_id, icmp_h->code);
		else
			printf(GREEN "(%d) icmp packet OK" RESET, th_id);
	}
	return ;
}

bool scan_syn( t_scan_port *port, const t_thread_arg *th_info )
{
	pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn(): port_nb = %d | ping_addr == %s\n", th_info->id, port->nb, inet_ntoa(th_info->host->ping_addr.sin_addr));pthread_mutex_unlock(&g_print_lock);
	uint8_t	retry = 0;
	// char	s_buf[IP_MAXPACKET] = {0};
	u_char	*r_buf = {0};
	// struct iphdr	ip_h;
	struct pcap_pkthdr	pkt_h;
	bzero(&pkt_h, sizeof(struct pcap_pkthdr));
	struct tcphdr	tcp_h;
	bzero(&tcp_h, sizeof(struct tcphdr));
	init_tcp_h(&tcp_h, port);

	// init_ip_h(&ip_h, host.ping_addr.sin_addr.s_addr);
	// memcpy(s_buf, &ip_h, sizeof(struct iphdr));
	// memcpy(s_buf, &tcp_h, sizeof(struct tcphdr));
	// memset(s_buf + sizeof(struct tcphdr), '0', IP_MAXPACKET - sizeof(struct tcphdr));

	//	FOR TESTS
	// struct in_addr	s_addr;
	
	for (; retry < 2; retry++)
	{
		// pthread_mutex_lock(&g_print_lock);printf("(%d) sendto(%s)\n", th_info->id, inet_ntoa(host.ping_addr.sin_addr));pthread_mutex_unlock(&g_print_lock);
		if (sendto(port->sockfd, &tcp_h, sizeof(struct tcphdr), 0, (struct sockaddr *)&(th_info->host->ping_addr), sizeof(struct sockaddr)) == -1)
			return (return_error("ft_nmap: syn: send_syn(): sendto()"));
		pthread_mutex_lock(&g_print_lock);printf("(%d) > sendto(): OK\n", th_info->id);pthread_mutex_unlock(&g_print_lock);

		bzero(r_buf, IP_MAXPACKET);
		r_buf = (u_char *)pcap_next(th_info->handle, &pkt_h);
		// if (recvfrom(port->sockfd, r_buf, 1024, 0 , NULL, NULL) == -1)
		// {
		// 	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT)
		// 	{
		// 		pthread_mutex_lock(&g_print_lock);printf(YELLOW "(%d) > recvfrom(): Timeout\n" RESET, th_info->id);pthread_mutex_unlock(&g_print_lock);
		// 		if (retry == 1)
		// 		{
		// 			//	NO REPONSE => STATE = FILTERED;
		// 			pthread_mutex_lock(&g_print_lock);printf(YELLOW "(%d) scan_syn: no response\n" RESET, th_info->id);pthread_mutex_unlock(&g_print_lock);
		// 		}
		// 		continue ;
		// 	}
		// 	else
		// 	{
		// 		return (return_error("ft_nmap: syn: send_syn(): recvfrom()"));	
		// 	}
		// }
		// else
		// {
		// 	tests_r_packet(r_buf);
		// 	s_addr.s_addr = ((struct iphdr *) r_buf)->saddr;	//	POUR LES TESTS
		// 	if (strcmp(inet_ntoa(s_addr), inet_ntoa(th_info->host->ping_addr.sin_addr)) == 0)
		// 	{
		// 		pthread_mutex_lock(&g_print_lock);printf(GREEN "(%d) > recvfrom(): source OK\n" RESET, th_info->id);pthread_mutex_unlock(&g_print_lock);
		// 	}
		// 	else
		// 	{
		// 		pthread_mutex_lock(&g_print_lock);printf(RED "(%d) > recvfrom(): source KO\n" RESET, th_info->id);pthread_mutex_unlock(&g_print_lock);
		// 	}
		// 	handle_return_packet(r_buf, port, th_info->id);
		// 	break ;
		// }
	}
	if (r_buf[0] != 0)
		handle_return_packet(r_buf, port, th_info->id);

	return (0);
}