#include "../../inc/nmap.h"

extern pthread_mutex_t	g_print_lock;

void	init_tcp_h( struct tcphdr *tcp_h, uint16_t *dst_port )
{
	bzero(tcp_h, sizeof(struct tcphdr));
	tcp_h->th_dport = htons(*dst_port);
	tcp_h->seq = htonl((unsigned int)rand());
	tcp_h->res1 = 4;
	tcp_h->doff = 5;
	tcp_h->syn = 1;
	tcp_h->th_win = htons(1024);
	tcp_h->th_sum = 0;
	tcp_h->th_urp = 0;
}

bool scan_syn( t_scan_port *port_info )
{
    printf("(%d) >>> scan_syn(): port_nb = %d, \n", port_info->th_id, port_info->nb);
	char	buf[IP_MAXPACKET] = {0};

	init_tcp_h(port_info->tcp_h, &(port_info->nb));
	port_info->tcp_h->check = checksum(port_info->tcp_h, sizeof(struct tcphdr));
	
	pthread_mutex_lock(&g_print_lock);
	printf("(%d) tcp_h->seq = %d \n", port_info->th_id, htons(port_info->tcp_h->seq));
	pthread_mutex_unlock(&g_print_lock);
	
	if (sendto(port_info->sockfd, port_info->tcp_h, sizeof(struct tcphdr), 0,	(struct sockaddr *)&(port_info->ping_addr),sizeof(struct sockaddr)) == -1)
		return (return_error("ft_nmap: syn: send_syn(): sendto()"));
	pthread_mutex_lock(&g_print_lock);
	printf("(%d) > sendto(): OK\n", port_info->th_id);
	pthread_mutex_unlock(&g_print_lock);

	if (recvfrom(port_info->sockfd, buf, 1024, 0 , NULL, NULL) == -1)
		return (return_error("ft_nmap: syn: send_syn(): recvfrom()"));	
	pthread_mutex_lock(&g_print_lock);
	printf("(%d) > recvfrom(): OK\n", port_info->th_id);
	pthread_mutex_unlock(&g_print_lock);

	struct iphdr	*r_ip = (struct iphdr *)buf;
	struct tcphdr	*r_tcp = (struct tcphdr *)(buf + r_ip->ihl * 4);
	(void) r_ip; (void) r_tcp;

	pthread_mutex_lock(&g_print_lock);
	printf("(%d) r_tcp->seq == %u | r_tcp->ack_seq == %u\n", port_info->th_id, r_tcp->seq, r_tcp->ack_seq);
	printf("(%d) r_tcp->ack = %d\n", port_info->th_id, r_tcp->ack);
	printf("(%d) r_tcp->syn = %d\n", port_info->th_id, r_tcp->syn);
	printf("(%d) r_tcp->src_addr = %d\n", port_info->th_id, htons(r_tcp->dest));
	printf("(%d) r_tcp->seq = %d\n", port_info->th_id, r_tcp->seq);
	// printf("(%d) r_tcp->fin = %d\n", port_info->th_id, r_tcp->fin);
	// printf("(%d) r_tcp->rst = %d\n", port_info->th_id, r_tcp->rst);
	// printf("(%d) r_tcp->psh = %d\n", port_info->th_id, r_tcp->psh);
	// printf("(%d) r_tcp->urg = %d\n", port_info->th_id, r_tcp->urg);
	pthread_mutex_unlock(&g_print_lock);
	return (0);
}