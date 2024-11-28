#include "../../inc/nmap.h"

// pour ecouter on doit creer un pcap_t *handle sur le quel on met les filtres et qui est utilisé pour recevoir les paquets
// le probleme c'est qu'on peut pas en créer qu'un parce qu'avec les threads ca va datarace i guess

// essayer de faire plusieurs thread qui utilise le handler, y'a moyen que ca fonctinne avec les versions plus a jour.

// envoie d'un paquet -> reception du paquet (mise en place du truc + les filtres) -> analyse de la reponse

void setup_filter(char *filter_str, pcap_t *handle)
{
	struct bpf_program filter;
	if (pcap_compile(handle, &filter, filter_str, 0, PCAP_NETMASK_UNKNOWN) == -1)
		fatal_error_str("Bad filter: %s\n", pcap_geterr(handle));
	if (pcap_setfilter(handle, &filter) == -1)
		fatal_error_str("Error setting filters: %s\n", pcap_geterr(handle));
	pcap_freecode(&filter);
}

pcap_t *init_handler(char *device)
{
	pcap_t *handle;
	int packet_count_limit = 1;
	int timeout_limit = 10000; /* In milliseconds */
	char error_buffer[PCAP_ERRBUF_SIZE];

	handle = pcap_open_live(device, BUFSIZ, packet_count_limit, timeout_limit, error_buffer);
	if (!handle)
		fatal_error_str("%s\n", error_buffer);
	return handle;
}

pcap_if_t *init_device(t_info *info)
{
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldvsp = NULL;
	pcap_addr_t *dev_addr;

	if (pcap_findalldevs(&alldvsp, error_buffer) == -1)
	{
		pcap_freealldevs(alldvsp);
		fatal_error_str("Nmap: pcap find device: %s\n", error_buffer);
	}
	if (!alldvsp)
		fatal_error("Nmap: no interface found\n");
	info->device = alldvsp->name;
	for (dev_addr = alldvsp->addresses; dev_addr != NULL; dev_addr = dev_addr->next) {
		if (dev_addr->addr && dev_addr->netmask &&
			dev_addr->addr->sa_family == AF_INET) {
			struct sockaddr_in *addr = (struct sockaddr_in *)dev_addr->addr;
			printf("  IP Address: %s\n", inet_ntoa(addr->sin_addr));
			info->ip_src = addr->sin_addr.s_addr;
			break;
		}
	}
	return alldvsp;
}

bool dns_lookup(char *input_domain, struct sockaddr_in *ping_addr)
{
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if ((getaddrinfo(input_domain, NULL, &hints, &res)) != 0)
		return (0);
	ping_addr->sin_family = AF_INET;
	ping_addr->sin_port = htons(0);
	ping_addr->sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
	freeaddrinfo(res);
	return (1);
}

bool fill_sockaddr_in(char *target, struct sockaddr_in *ping_addr) 
{
	memset(ping_addr, 0, sizeof(struct sockaddr_in));

	// tcheck si c'est une address ipv4
	if (inet_pton(AF_INET, target, &ping_addr->sin_addr) == 1) {
		ping_addr->sin_family = AF_INET;
		ping_addr->sin_port = htons(0);
		return (1);
	}
	if (!dns_lookup(target, ping_addr))
		return (0);
	return (1);
}

void	scan_switch( t_scan_port *port, t_host *host, const uint8_t scan_type, const uint8_t th_id)
{
	switch (scan_type)
	{
		case ALL:
			scan_all(port, host, th_id);
			break ;
		case SYN:
			scan_syn(port, *host, th_id);
			break ;
		case S_NULL:
			scan_null(port, *host, th_id);
			break ;
		case ACK:
			scan_ack(port, *host, th_id);
			break ;
		case FIN:
			scan_fin(port, *host, th_id);
			break ;
		case XMAS:
			scan_xmas(port, *host, th_id);
			break ;
		case UDP:
			scan_udp(port, *host, th_id);
			break ;
		default:
			break ;
	}
}

bool scan_all( t_scan_port *port, t_host *host, const uint8_t th_id )
{
	(void)host;
	(void) th_id;
	// t_info	*info = NULL; //  A RETIRER !!!!
	printf("(%d)scan ALL\n", th_id);
	scan_syn(port, *host, th_id);
	scan_null(port, *host, th_id);
	scan_ack(port, *host, th_id);
	scan_fin(port, *host, th_id);
	scan_xmas(port, *host, th_id);
	scan_udp(port, *host, th_id);
	return (0); 
}

void scan(t_info *info, t_host *host)
{
	pcap_if_t *alldvsp = NULL;
	pcap_t *handle = NULL;
	uint16_t	port = info->first_port;
	uint16_t	last_port = info->first_port + info->port_range;

	alldvsp = init_device(info);
	handle = init_handler(info->device);

	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd == -1)
	{
		pcap_freealldevs(alldvsp);
		pcap_close(handle);
		fatal_perror("ft_nmap: socket");
	}
	host->ip_src = info->ip_src;
	for (; port < last_port; port++)
	{
		host->port_tab[port - info->first_port].nb = port;
		host->port_tab[port - info->first_port].sockfd = sockfd;
		scan_switch(&host->port_tab[port - info->first_port], host, info->scan_type, NO_THREAD);
	}

	pcap_freealldevs(alldvsp);
	pcap_close(handle);
}
