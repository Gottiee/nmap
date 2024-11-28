#include "../../inc/nmap.h"

extern pthread_mutex_t	g_print_lock;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	(void)args;
	(void)header;
	(void)packet;
}

void read_response(pcap_t *handle)
{
	pcap_loop(handle, 1, packet_handler, NULL);
}

void fill_ip(struct iphdr *iph, char *datagram, t_host *host, char *data)
{
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof(struct udphdr) + strlen(data);
	iph->id = htonl(getpid());
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = host->ip_src.s_addr;
	iph->daddr = host->ping_addr.sin_addr.s_addr;
	iph->check = checksum((unsigned short *)datagram, iph->tot_len);
}

void fill_udp(struct udphdr *udph, t_scan_port *port, char *data)
{
	udph->source = htons(6666);
	udph->dest = htons(port->nb);
	udph->len = htons(8 + strlen(data));
	udph->check = checksum(udph, sizeof(struct udphdr));
}

bool scan_udp( t_scan_port *port, t_host host, const int16_t th_id )
{
	g_handle[th_id] = host.handle;
	pcap_t *handler;

	if (th_id == NO_THREAD)
		handler = host.handle;
	else
		handler = port->handle;
	
	char  filter[4096];
	char datagram[4096], *data;
	int fds = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (fds < 0)
	{
		perror("Nmap: socket udp");
		return false;
	}
	memset(datagram, 0, 4096);
	struct iphdr *iph = (struct iphdr *)datagram;
	struct udphdr *udph = (struct udphdr *)(datagram +sizeof (struct iphdr));
	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	strcpy(data, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	fill_ip(iph, datagram, &host, data);
	fill_udp(udph, port, data);

	printf("(%d) socket %d | datagram %p | len %d | 0 | addr = %d\n", th_id, port->sockfd, datagram, iph->tot_len, host.ping_addr.sin_addr.s_addr);
	if (sendto(port->sockfd, datagram, iph->tot_len, 0, (struct sockaddr *) &host.ping_addr, sizeof(host.ping_addr)) < 0)
	{
		perror("Nmap error sending udp packet");
		return false;
	}
	sprintf(filter, "(udp and dst port %d and ip dst %s)", port->nb, inet_ntoa(host.ping_addr.sin_addr));
	printf("Filter = %s\n", filter);
	setup_filter(filter, handler);
	alarm(1);
	read_response(handler);
	port->state = OPEN;
	return true;
}