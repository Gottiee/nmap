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

uint16_t	get_checksum( const struct sockaddr_in *dst_addr, const struct tcphdr *tcp_h )
{
	(void)dst_addr;
	t_pseudo_hdr	psh = {0};
	char	pseudogram[sizeof(t_pseudo_hdr) + sizeof(struct tcphdr)] = {0};
	// get_local_ip(tmp_ip_str, &tmp_ip);
	// inet_pton(AF_INET, tmp_ip_str, &tmp_ip);
	// pseudo_hdr.dest_ip = dst_addr->sin_addr.s_addr;
	// pseudo_hdr.proto = IPPROTO_TCP;
	// pseudo_hdr.tcp_len = sizeof(struct tcphdr);
	// memcpy(raw_pseudo_hdr, (char *)&pseudo_hdr, sizeof(pseudo_hdr));

	psh.source_address = inet_addr("10.0.2.15");  // Adresse source
	psh.dest_address = dst_addr->sin_addr.s_addr;  // Adresse de destination
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));

	memcpy(pseudogram, (char *)&psh, sizeof(t_pseudo_hdr));
	memcpy(pseudogram + sizeof(t_pseudo_hdr), tcp_h, sizeof(struct tcphdr));
	return(checksum((unsigned short *)pseudogram, sizeof(t_pseudo_hdr) + sizeof(struct tcphdr)));
}

void	init_ip_h( struct iphdr *iph, const uint32_t dest_addr )
{
	iph->ihl = 5;
	iph->version = IPVERSION;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	iph->id = htonl(syscall(SYS_gettid));
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr("10.0.2.15");
	iph->daddr = dest_addr;
}

void	init_tcp_h( struct tcphdr *tcph, const uint16_t port_nb, const struct sockaddr_in *dest_addr )
{
	(void) dest_addr;
	tcph->source = htons(34978);
	tcph->dest = htons(port_nb);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->window = htons(5840);
	tcph->check = 0;
}

void	init_tcp_opt( uint8_t options[4] )
{
	// Add MSS Option
	options[0] = 2;
	options[1] = 4;  // Length of MSS option
	*(uint16_t *)&options[2] = htons(1460); // MSS value (1460 bytes)
}

void	tests_r_packet( const u_char r_buf[IP_MAXPACKET], const uint8_t th_id )
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

bool	handle_return_packet( const u_char *r_buf, t_scan_port *port, const uint8_t th_id )
{
	pthread_mutex_lock(&g_print_lock);printf("(%d) In handle_return_packet()\n", th_id);pthread_mutex_unlock(&g_print_lock);
	tests_r_packet(r_buf, th_id);
	
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

bool scan_syn( t_scan_port *port, const t_thread_arg *th_info )
{
	pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn(): port_nb(%p) = %d | ping_addr == %s\n", th_info->id, &(port->nb), port->nb, inet_ntoa(th_info->host.ping_addr.sin_addr));pthread_mutex_unlock(&g_print_lock);

	uint8_t	retry = 0;
	const u_char	*r_data = NULL;
	char	filter_str[27 + INET_ADDRSTRLEN + 1] = {0};
	int		ret_val = 0;
	struct pcap_pkthdr	*pkt_h = NULL;
	struct pollfd	pollfd = {0};
	
	char packet[4096];
	struct iphdr *iph = (struct iphdr *) packet;
	struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct iphdr));
	
	init_ip_h(iph, th_info->host.ping_addr.sin_addr.s_addr);
	iph->check = checksum((unsigned short *)packet, iph->tot_len);
	init_tcp_h(tcph, port->nb, &th_info->host.ping_addr);
	tcph->check = get_checksum(&th_info->host.ping_addr, tcph);
	
	pollfd.events = POLLIN;
	pollfd.fd = pcap_get_selectable_fd(th_info->handle);
	if (pollfd.fd == -1)
		fatal_perror("ft_nmap: pcap_get_selectable_fd");
	pthread_mutex_lock(&g_print_lock);printf("(%d)tcp_h.source == %d\n", th_info->id, tcph->source);pthread_mutex_unlock(&g_print_lock);

	for (; retry < 2; retry++)
	{
		sprintf(filter_str, "src host %s and (tcp or icmp)", inet_ntoa(th_info->host.ping_addr.sin_addr));
		setup_filter(filter_str, th_info->handle);
		pthread_mutex_lock(&g_print_lock);\
		printf("(%d) sockaddr_in : addr => %s | port == %d | family == %d\n", 
			th_info->id, inet_ntoa(th_info->host.ping_addr.sin_addr), th_info->host.ping_addr.sin_port, th_info->host.ping_addr.sin_family);
		pthread_mutex_unlock(&g_print_lock);
		if (sendto(port->sockfd, packet, iph->tot_len, 0, 
			(struct sockaddr *)&(th_info->host.ping_addr), sizeof(struct sockaddr)) == -1)
			return (return_error("ft_nmap: syn: sendto(): sendto()"));
		pthread_mutex_lock(&g_print_lock);printf("(%d) > sendto(p: %hhu): OK\n", th_info->id, port->nb);pthread_mutex_unlock(&g_print_lock);

		ret_val = poll(&pollfd, 1, 2000);
		if (ret_val == -1)
			fatal_perror("ft_nmap: poll");
		else if (ret_val == 0)
		{
			printf(RED ">>> poll() TO\n" RESET);
			continue ;
		}
		int ret_val = pcap_next_ex(th_info->handle, &pkt_h, &r_data);
		if (ret_val == 1)
		{
			pthread_mutex_lock(&g_print_lock);printf( GREEN "(%d) > pcap_next(): received\n RESET", th_info->id);pthread_mutex_unlock(&g_print_lock);
			handle_return_packet(r_data, port, th_info->id);
		}
		else if (ret_val == 0)
		{
			printf( RED "(%d) >>> pcap_next(): TO\n"RESET, th_info->id);
		}
		else if (ret_val == PCAP_ERROR_ACTIVATED)
		{
			printf( RED "(%d) >>> pcap_next(): capture created but not activated\n "RESET, th_info->id);
		}
		else if (ret_val == PCAP_ERROR)
		{
			printf( RED "(%d) >>> pcap_next(): ERROR\n "RESET, th_info->id);
		}
		else
		{
			pthread_mutex_lock(&g_print_lock);printf("(%d) ret_val == 0\n", th_info->id);pthread_mutex_unlock(&g_print_lock);
		}


		// bzero(r_buf, IP_MAXPACKET);
		// socklen_t	len = sizeof(struct sockaddr);
		// if (recvfrom(port->sockfd, r_buf, IP_MAXPACKET, 0, (struct sockaddr *)&th_info->host.ping_addr, &len) == -1)
		// {
		// 	if (errno == ETIMEDOUT)
		// 		printf(" >>> recfrom(): TO \n");
		// 	else
		// 		printf("Recvfrom fail\n");
		// }
		// handle_return_packet(r_data, port, th_info->id);
	}
	

	return (0);
}