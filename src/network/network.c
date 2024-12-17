#include "../../inc/nmap.h"

// pour ecouter on doit creer un pcap_t *handle sur le quel on met les filtres et qui est utilisé pour recevoir les paquets
// le probleme c'est qu'on peut pas en créer qu'un parce qu'avec les threads ca va datarace i guess

// essayer de faire plusieurs thread qui utilise le handler, y'a moyen que ca fonctinne avec les versions plus a jour.

// envoie d'un paquet -> reception du paquet (mise en place du truc + les filtres) -> analyse de la reponse

uint16_t get_random_port( void )
{
    return (syscall(SYS_gettid) + rand() % (65535 - 49152 + 1) + 49152);
}

void setup_filter(char *filter_str, pcap_t *handle)
{
	struct bpf_program filter;
	printf("pcap_filter -> [%s]\n", filter_str);
	if (pcap_compile(handle, &filter, filter_str, 0, PCAP_NETMASK_UNKNOWN) == -1)
	{
		printf("Bad filter: %s\n", filter_str);
		fatal_error_str("Bad filter: %s\n", pcap_geterr(handle));
	}
	// sprintf(str_filter, "src host %s and (tcp or icmp)", ip_buf);
	if (pcap_setfilter(handle, &filter) == -1)
		fatal_error_str("Error setting filters: %s\n", pcap_geterr(handle));
	pcap_freecode(&filter);
}

pcap_t *init_handler(char *device)
{
	pcap_t *handle;
	// int packet_count_limit = 1;
	// int timeout_limit = 10000; /* In milliseconds */
	char error_buffer[PCAP_ERRBUF_SIZE];

	(void) device;
	// handle = pcap_open_live("enp0s3", BUFSIZ, packet_count_limit, timeout_limit, error_buffer);
	// if (!handle)
	// 	fatal_error_str("%s\n", error_buffer);
	handle = pcap_create("any", error_buffer);
	if (handle == NULL)
		fatal_error("pcap_create()");
	 if (pcap_set_snaplen(handle, 100) != 0) {
		fatal_error("pcap_create()");
    }
    if (pcap_set_immediate_mode(handle, 1) != 0) {
		fatal_error("pcap_immeiatrjfhwae_mode()");
    }
    if (pcap_set_timeout(handle, 500) != 0) {
		fatal_error("pcap_timeout()");
    }
    if (pcap_setnonblock(handle, 1, NULL) != 0) {
		fatal_error("pcap_setnoblock()");
    }
    if (pcap_set_promisc(handle, 1) != 0) {
		fatal_error("pcap_set_promisc()");
    }
    if (pcap_activate(handle) != 0) {
		fatal_error("pcap_activate()");
    }
    if (pcap_datalink(handle) != DLT_LINUX_SLL) {
		fatal_error("pcap_datalink()");
    }
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
			// printf("  IP Address: %s\n", inet_ntoa(addr->sin_addr));
			info->ip_src = addr->sin_addr;
			break;
		}
	}
	return alldvsp;
}

bool dns_lookup(char *input_domain, struct sockaddr_in *ping_addr)
{
	(void)input_domain;
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

void	scan_switch( t_scan_port *port, const t_thread_arg *th_info)
{
	// printf("scan_switch: addr = %s\n", inet_ntoa(host->ping_addr.sin_addr));
	switch (th_info->scan_type)
	{
		case ALL:
			scan_all(port, th_info);
			break ;
		case SYN:
			scan_syn(port, th_info);
			break ;
		case S_NULL:
			scan_null(port, th_info);
			break ;
		case ACK:
			scan_ack(port, th_info);
			break ;
		case FIN:
			scan_fin(port, th_info);
			break ;
		case XMAS:
			scan_xmas(port, th_info);
			break ;
		case UDP:
			scan_udp(port, th_info);
			break ;
		default:
			break ;
	}
}

bool scan_all( t_scan_port *port, const t_thread_arg *th_info )
{
	// t_info	*info = NULL; //  A RETIRER !!!!
	// printf("(%d)scan ALL\n", th_id);
	scan_syn(port, th_info);
	scan_null(port, th_info);
	scan_ack(port, th_info);
	scan_fin(port, th_info);
	scan_xmas(port, th_info);
	scan_udp(port, th_info);
	return (0); 
}

void	init_th_info( t_thread_arg *th_info, t_info *info, pcap_if_t *alldvsp, pcap_t *handle )
{
	th_info->handle = init_handler(info->device);
	th_info->scan_type = info->scan_type;
	th_info->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	th_info->ip_src = info->ip_src;
	if (th_info->sockfd == -1)
	{
		pcap_freealldevs(alldvsp);
		pcap_close(handle);
		fatal_perror("ft_nmap: socket");
	}
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	if (setsockopt(th_info->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0)
	{
		pcap_freealldevs(alldvsp);
		pcap_close(handle);
		fatal_perror("ft_nmap: setsockopt");
	}
}

void scan(struct sockaddr_in *ping_addr, t_info *info, t_host *host)
{
	pcap_if_t *alldvsp = NULL;
	pcap_t *handle = NULL;
	uint16_t	port = info->first_port;
	uint16_t	last_port = info->first_port + info->port_range;
	t_thread_arg	th_info = {0};

	// liste les devices et utilse le premier device utiliser la premiere interface trouvée (peut etre le secure ca)
	alldvsp = init_device(info);
	// creer un handler, qui va servir à ecouter sur l'interface seletionnée
	handle = init_handler(alldvsp->name);

	init_th_info(&th_info, info, alldvsp, handle);
	host->ping_addr = *ping_addr;
	th_info.host = *host;
	th_info.id = 0;
	


	for (; port < last_port; port++)
	{
		host->port_tab[port - info->first_port].nb = port;
		scan_switch(&host->port_tab[port - info->first_port], &th_info);
	}

	pcap_freealldevs(alldvsp);
	pcap_close(handle);
}
