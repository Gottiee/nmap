#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <time.h>		//	time()
#include <stdlib.h> 	//	rand()
#include <strings.h>	//	bzero()
#include <string.h>
#include <sys/types.h>
#include <netdb.h>

bool	return_error( char *err_mess )
{
	perror(err_mess);
	return (1);
}

unsigned short checksum(void *b, int len) {
	unsigned short *buf = b;
	unsigned int sum = 0;
	unsigned short result;
	for (sum = 0; len > 1; len -= 2)
		sum += *buf++;
	if (len == 1)
		sum += *(unsigned char *)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

bool dns_lookup(char *input_domain, struct sockaddr_in *ping_addr)
{
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(input_domain, NULL, &hints, &res) != 0)
		return(return_error("ft_nmap: syn: dns_lookup()"));
	ping_addr->sin_family = AF_INET;
	ping_addr->sin_port = htons(0);
	ping_addr->sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
	freeaddrinfo(res);
	return 0;
}

void	init_tcp_h( struct tcphdr *tcp_h, uint16_t *src_port, uint16_t *dst_port )
{
	bzero(tcp_h, sizeof(struct tcphdr));
	tcp_h->source = htons(*src_port);
	tcp_h->dest = htons(*dst_port);
	tcp_h->seq = htonl((unsigned int)rand());
	tcp_h->ack_seq = htonl(0);
	tcp_h->res1 = 4;
	tcp_h->doff = 5;
	tcp_h->syn = 1;
	tcp_h->window = htons(1024);
	tcp_h->check = 0;
	tcp_h->urg_ptr = 0;
}

bool	send_syn( struct tcphdr *tcp_h, int *sockfd, struct sockaddr *addr )
{
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

int	main( int argc, char **argv )
{
	( void ) argc;
	uint16_t	ports[1024] = {0};
	for (uint16_t i = 0; i < 1024; i++)
		ports[i] = i;
	
	int	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	// int	sockfd = -1;
	if (sockfd == -1)
		return_error("ft_nmap: syn: socket()");
	struct tcphdr	tcp_h;	
	struct sockaddr	addr;
	bzero(&addr, sizeof(struct sockaddr));
	
	srand(time(NULL));
	init_tcp_h(&tcp_h, );

	if (dns_lookup(argv[1], (struct sockaddr_in *)&addr) == 1)
		return (1);

	if (send_syn(&tcp_h, &sockfd, &addr) == 1)
		return (1);
	
	return (0);
}