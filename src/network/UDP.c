#include "../../inc/nmap.h"

// extern pthread_mutex_t	g_print_lock;


// void fill_ip(struct iphdr *iph, char *datagram, t_host *host, char *data)
// {
// 	iph->ihl = 5;
// 	iph->version = 4;
// 	iph->tos = 0;
// 	iph->tot_len = sizeof (struct iphdr) + sizeof(struct udphdr) + strlen(data);
// 	iph->id = htonl(getpid());
// 	iph->frag_off = 0;
// 	iph->ttl = 64;
// 	iph->protocol = IPPROTO_UDP;
// 	iph->saddr = host->ip_src;
// 	iph->daddr = host->ping_addr.sin_addr.s_addr;
// 	iph->check = checksum((unsigned short *)datagram, iph->tot_len);
// }

// void fill_udp(struct udphdr *udph, t_scan_port *port, char *data)
// {
// 	udph->source = htons(6666);
// 	udph->dest = htons(port->nb);
// 	udph->len = htons(8 + strlen(data));
// 	udph->check = checksum(udph, sizeof(struct udphdr));
// }

bool scan_udp( t_scan_port *port, const t_thread_arg *th_info )
{
	(void)th_info;
	(void)port;

// 	char datagram[4096], *data;
// 	int fds = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
// 	if (fds < 0)
// 	{
// 		perror("Nmap: socket udp");
// 		return false;
// 	}
// 	memset(datagram, 0, 4096);
// 	struct iphdr *iph = (struct iphdr *)datagram;
// 	struct udphdr *udph = (struct udphdr *)(datagram +sizeof (struct iphdr));
// 	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
// 	strcpy(data, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
// 	fill_ip(iph, datagram, &host, data);
// 	fill_udp(udph, port, data);

// 	// if (sendto(port->sockfd, datagram, iph->tot_len, 0, (struct sockaddr *) &host.ping_addr, sizeof(host.ping_addr)) < 0)
// 	// {
// 	// 	perror("Nmap error sending udp packet");
// 	// 	return false;
// 	// }
// 	// else
// 	// 	printf(" >> Udp packet sent\n");
// 	port->state = OPEN;
	return true;
}