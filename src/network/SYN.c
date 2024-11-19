#include "../../inc/nmap.h"

bool scan_syn()
{
    printf(">>> scan_syn\n");
	char	buf[IP_MAXPACKET] = {0};

	tcp_h->check = checksum(tcp_h, sizeof(struct tcphdr));
	
	printf("tcp_h->seq = %d \n", htons(tcp_h->seq));
	
	if (sendto(*sockfd, tcp_h, sizeof(struct tcphdr), 0, addr, sizeof(*addr)) == -1)
		return (return_error("ft_nmap: syn: send_syn(): sendto()"));
	printf("> sendto(): OK\n");
	if (recvfrom(*sockfd, buf, 1024, 0 , NULL, NULL) == -1)
		return (return_error("ft_nmap: syn: send_syn(): recvfrom()"));
	printf("> recvfrom(): OK\n");

	struct iphdr	*r_ip = (struct iphdr *)buf;
	int	l_r_ip = r_ip->ihl * 4;
	struct tcphdr	*r_tcp = (struct tcphdr *)(buf + l_r_ip);
	(void) r_ip; (void) r_tcp;

	printf("r_tcp->seq == %u | r_tcp->ack_seq == %u\n", r_tcp->seq, r_tcp->ack_seq);
	printf("r_tcp->ack = %d\n", r_tcp->ack);
	printf("r_tcp->syn = %d\n", r_tcp->syn);
	printf("r_tcp->fin = %d\n", r_tcp->fin);
	printf("r_tcp->rst = %d\n", r_tcp->rst);
	printf("r_tcp->psh = %d\n", r_tcp->psh);
	printf("r_tcp->urg = %d\n", r_tcp->urg);
	return (0);
}