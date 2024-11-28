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

pcap_if_t *init_device()
{
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldvsp = NULL;

	/* Find a device */
	if (pcap_findalldevs(&alldvsp, error_buffer))
		fatal_error_str("%s\n", error_buffer);
	return alldvsp;
}

bool dns_lookup(char *input_domain, struct sockaddr_in *ping_addr)
{
	(void)input_domain;
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if ((getaddrinfo("172.217.20.174", NULL, &hints, &res)) != 0)
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
	printf("scan_switch: addr = %d\n", host->ping_addr.sin_addr.s_addr);
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

void scan(struct sockaddr_in *ping_addr, t_info *info, t_host *host)
{
	(void)ping_addr;
	(void)host;
	(void)info;
	pcap_if_t *alldvsp = NULL;
	pcap_t *handle = NULL;
	uint16_t	port = info->first_port;
	uint16_t	last_port = info->first_port + info->port_range;

	// liste les devices et utilse le premier device utiliser la premiere interface trouvée (peut etre le secure ca)
	alldvsp = init_device();
	// creer un handler, qui va servir à ecouter sur l'interface seletionnée
	handle = init_handler(alldvsp->name);

	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd == -1)
	{
		pcap_freealldevs(alldvsp);
		pcap_close(handle);
		fatal_perror("ft_nmap: socket");
	}

	for (; port < last_port; port++)
	{
		host->port_tab[port - info->first_port].nb = port;
		scan_switch(&host->port_tab[port - info->first_port], host, info->scan_type, NO_THREAD);
	}

	pcap_freealldevs(alldvsp);
	pcap_close(handle);
}
