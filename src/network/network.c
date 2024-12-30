#include "../../inc/nmap.h"
//	ERROR OK

// pour ecouter on doit creer un pcap_t *handle sur le quel on met les filtres et qui est utilisé pour recevoir les paquets
// le probleme c'est qu'on peut pas en créer qu'un parce qu'avec les threads ca va datarace i guess

// essayer de faire plusieurs thread qui utilise le handler, y'a moyen que ca fonctinne avec les versions plus a jour.

// envoie d'un paquet -> reception du paquet (mise en place du truc + les filtres) -> analyse de la reponse

uint16_t get_random_port( void )
{
    return (syscall(SYS_gettid) + rand() % (65535 - 49152 + 1) + 49152);
}

bool setup_filter(char *filter_str, pcap_t *handle)
{
	struct bpf_program filter;
	// printf("handle == %p\n", handle);
	if (pcap_compile(handle, &filter, filter_str, 0, PCAP_NETMASK_UNKNOWN) == -1)
	{
		// printf("Bad filter: %s\n", filter_str);
		pthread_mutex_lock(&g_lock);
		g_done = 1;
		pthread_mutex_unlock(&g_lock);
		fprintf(stderr, "ft_nmap: pcap_compile: %s\n", pcap_geterr(handle));
		return (1);
	}
	if (pcap_setfilter(handle, &filter) == -1)
	{
		pthread_mutex_lock(&g_lock);
		g_done = 1;
		pthread_mutex_unlock(&g_lock);
		pcap_freecode(&filter);
		fprintf(stderr, "ft_nmap: set_filter: %s\n", pcap_geterr(handle));
		return (1);
	}
	pcap_freecode(&filter);
	return (0);
}

pcap_t *init_handler( void )
{
	pcap_t *handle = NULL;
	char error_buffer[PCAP_ERRBUF_SIZE] = {0};

	if (g_info->options.interface != NULL)
		handle = pcap_create(g_info->options.interface, error_buffer);
	else
		handle = pcap_create("any", error_buffer);
	if (handle == NULL)
	{
		fprintf(stderr, "ft_nmap: pcap_create: %s\n", error_buffer);
		return (NULL);
	}
	if (pcap_set_snaplen(handle, 100) != 0)
	{
		pcap_close(handle);
		fprintf(stderr, "ft_nmap: pcap_create: %s\n", error_buffer);
		return (NULL);
    }
    if (pcap_set_immediate_mode(handle, 1) != 0)
	{
		pcap_close(handle);
		fprintf(stderr, "ft_nmap: pcap_immediate_mode: %s\n", error_buffer);
		return (NULL);
    }
    if (pcap_set_timeout(handle, 500) != 0)
	{
		pcap_close(handle);
		fprintf(stderr, "ft_nmap: pcap_timeout: %s", error_buffer);
		return (NULL);
    }
    if (pcap_setnonblock(handle, 1, NULL) != 0)
	{
		pcap_close(handle);
		fprintf(stderr, "ft_nmap: pcap_setnoblock: %s\n", error_buffer);
		return (NULL);
    }
    if (pcap_set_promisc(handle, 1) != 0)
	{
		pcap_close(handle);
		fprintf(stderr, "ft_nmap: pcap_set_promisc: %s\n/", error_buffer);
		return (NULL);
    }
    if (pcap_activate(handle) != 0)
	{
		pcap_close(handle);
		fprintf(stderr, "Quitting!\n Unknown interface: %s\n", g_info->options.interface);
		return (NULL);
    }
    if (pcap_datalink(handle) != DLT_LINUX_SLL)
	{
		pcap_close(handle);
		fprintf(stderr, "ft_nmap: pcap_datalink: %s\n", error_buffer);
		return (NULL);
    }
	return handle;
}

pcap_if_t *init_device(t_info *info)
{
	char error_buffer[PCAP_ERRBUF_SIZE] = {0};
	pcap_if_t *alldvsp = info->alldvsp;
	pcap_addr_t *dev_addr;

	if (pcap_findalldevs(&alldvsp, error_buffer) == -1)
	{
		pcap_freealldevs(alldvsp);
		fprintf(stderr, "Nmap: pcap find device: %s\n", error_buffer);
		return (NULL);
	}
	if (!alldvsp)
	{
		fprintf(stderr, "Nmap: no interface found\n");
		return (NULL);
	}
	info->device = alldvsp->name;
	for (dev_addr = alldvsp->addresses; dev_addr != NULL; dev_addr = dev_addr->next)
	{
		if (dev_addr->addr && dev_addr->netmask && dev_addr->addr->sa_family == AF_INET)
		{
			struct sockaddr_in *addr = (struct sockaddr_in *)dev_addr->addr;
			// printf("  IP Address: %s\n", inet_ntoa(addr->sin_addr));
			info->ip_src = addr->sin_addr;
			break;
		}
	}
	return alldvsp;
}

void	init_ip_h( struct iphdr *iph, const t_thread_arg *th_info, const uint8_t protocol )
{
	iph->ihl = 5;
	iph->version = IPVERSION;
	if (protocol == IPPROTO_TCP)
		iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	if (protocol == IPPROTO_UDP)
		iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + UDP_PAYLOAD_SIZE;
	iph->id = htonl(syscall(SYS_gettid));
	iph->ttl = g_info->options.ttl;
	iph->protocol = protocol;
	iph->saddr = th_info->ip_src.s_addr;
	iph->daddr = th_info->host->ping_addr.sin_addr.s_addr;
}

uint16_t	get_checksum( const t_thread_arg *th_info, void *header, const uint8_t protocol )
{
	t_pseudo_hdr	psh = {0};
	char	pseudogram_tcp[sizeof(t_pseudo_hdr) + sizeof(struct tcphdr)] = {0};
	char	pseudogram_udp[sizeof(t_pseudo_hdr) + sizeof(struct udphdr) + UDP_PAYLOAD_SIZE] = {0};
	struct tcphdr	*tcph = NULL;
	struct udphdr	*udph = NULL;

	if (protocol == IPPROTO_TCP)
		tcph = header;
	else if (protocol == IPPROTO_UDP)
		udph = header;
	

	psh.source_address = th_info->ip_src.s_addr;  // Adresse source
	psh.dest_address = th_info->host->ping_addr.sin_addr.s_addr;  // Adresse de destination
	psh.placeholder = 0;
	psh.protocol = protocol;

	if (protocol == IPPROTO_TCP)
		psh.tcp_length = htons(sizeof(struct tcphdr));
	if (protocol == IPPROTO_UDP)
		psh.tcp_length = htons(sizeof(struct udphdr) + UDP_PAYLOAD_SIZE);

	if (protocol == IPPROTO_TCP)
	{
		memcpy(pseudogram_tcp, (char *)&psh, sizeof(t_pseudo_hdr));
		memcpy(pseudogram_tcp + sizeof(t_pseudo_hdr), tcph, sizeof(struct tcphdr));
		return(checksum((unsigned short *)pseudogram_tcp, sizeof(t_pseudo_hdr) + sizeof(struct tcphdr)));
	}
	else if (protocol == IPPROTO_UDP)
	{
		memcpy(pseudogram_udp, (char *)&psh, sizeof(t_pseudo_hdr));
		memcpy(pseudogram_udp + sizeof(t_pseudo_hdr), udph, sizeof(struct udphdr) + UDP_PAYLOAD_SIZE);
		return(checksum((unsigned short *)pseudogram_udp, sizeof(t_pseudo_hdr) + sizeof(struct udphdr) + UDP_PAYLOAD_SIZE));
	}
	
	return (0);
}

bool dns_lookup(char *input_domain, struct sockaddr_in *ping_addr)
{
	(void)input_domain;
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(input_domain, NULL, &hints, &res) != 0)
		return (0);
	ping_addr->sin_family = AF_INET;
	ping_addr->sin_port = htons(0);
	ping_addr->sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
	freeaddrinfo(res);
	return (1);
}

bool send_recv_packet( t_scan_port *port, t_thread_arg *th_info, struct pollfd pollfd, char packet[4096], struct iphdr *iph )
{
	(void)packet;(void) iph;
	uint8_t	retry = 0;
	int		ret_val = 0;
	const u_char	*r_data = NULL;
	struct pcap_pkthdr	*pkt_h = NULL;

	for (; retry < g_info->options.nb_retries; retry++)
	{
		if (sendto(th_info->sockfd, packet, iph->tot_len, 0, 
			(struct sockaddr *)&(th_info->host->ping_addr), sizeof(struct sockaddr)) == -1)
		{
			pthread_mutex_lock(&g_lock);
			g_done = 1;
			pthread_mutex_unlock(&g_lock);
			// pcap_close(th_info->handle);
			fprintf(stderr, "ft_nmap: sendto: %s\n", strerror(errno));
			return (1);
		}

	arm_poll:
		ret_val = poll(&pollfd, 1, 400);
		if (ret_val == -1)
		{
			pthread_mutex_lock(&g_lock);
			g_done = 1;
			pthread_mutex_unlock(&g_lock);
			// pcap_close(th_info->handle);
			fprintf(stderr, "ft_nmap: poll: %s\n", strerror(errno));
			return (1);
		}
		else if (ret_val == 0)
		{
			continue ;
		}
		else if (ret_val >= 0 && pollfd.revents & POLLIN)
		{
			ret_val = pcap_next_ex(th_info->handle, &pkt_h, &r_data);
			if (ret_val == 1)
			{
				// pthread_mutex_lock(&g_print_lock);printf( GREEN "(%d) > pcap_next(%d): received\n " RESET, th_info->id, port->nb);pthread_mutex_unlock(&g_print_lock);
				handle_return_packet(r_data, port, th_info->id, th_info->scan_type, th_info->host);
				break ;
			}
			else if (ret_val == 0)
			{
				printf("(%d) >>> pcap_next(%d): timed out\n", th_info->id, port->nb);
				goto arm_poll;
			}
			else 
			{
				pthread_mutex_lock(&g_lock);
				g_done = 1;
				pthread_mutex_unlock(&g_lock);
				char	err_str[PCAP_ERRBUF_SIZE] = {0};
				sprintf(err_str, "ft_nmap: pcap_next_ex: %s\n", pcap_geterr(th_info->handle));
				// pcap_close(th_info->handle);
				fprintf(stderr, "ft_nmap: pcap_next_ex: %s\n", err_str);
				return (1);
			}
		}
	}
	return (0);
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

bool scan_all( t_scan_port *port, t_thread_arg th_info )
{
	for (uint8_t i = SYN; i <= XMAS; i++)
	{
		th_info.scan_type = i;
		if (scan_tcp(port, &th_info) == 1)
			return (1);
	}
	th_info.scan_type = UDP;
	scan_udp(port, &th_info);

	return (0); 
}

bool	scan_switch( t_scan_port *port, t_thread_arg *th_info)
{
	if (th_info->scan_type <= XMAS)
	{
		if (scan_tcp(port, th_info) == 1)
			return (1);
	}
	else if (th_info->scan_type == UDP)
	{
		if (scan_udp(port, th_info) == 1)
			return (1);
	}
	else if (th_info->scan_type == ALL)
		scan_all(port, *th_info);
	return (0);
}

void	init_th_info( t_thread_arg *th_info, t_info *info )
{
	th_info->handle = init_handler();
	th_info->scan_type = info->scan_type[0];
	th_info->ip_src = info->ip_src;
	th_info->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (th_info->sockfd == -1)
	{
		pcap_close(th_info->handle);
		fatal_perror("ft_nmap: socket");
	}
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	if (setsockopt(th_info->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0)
	{
		pcap_close(th_info->handle);
		fatal_perror("ft_nmap: setsockopt");
	}
}

void scan(struct sockaddr_in *ping_addr, t_info *info, t_host *host)
{
	uint16_t	port = info->first_port;
	uint16_t	last_port = info->first_port + info->port_range;
	t_thread_arg	th_info = {0};

	init_th_info(&th_info, info);
	host->ping_addr = *ping_addr;
	th_info.host = host;
	th_info.id = 0;
	
	for (; port < last_port; port++)
	{
		for (uint8_t scan = 0; scan < NB_MAX_SCAN && info->scan_type[scan] != -1; scan++)	// run through scan types
		{
			host->port_tab[port - info->first_port].nb = port;
			th_info.scan_type = info->scan_type[scan];
			if (scan_switch(&host->port_tab[port - info->first_port], &th_info) == 1)
				goto end_scan;
		}
	}
	end_scan:
		pcap_close(th_info.handle);
}
