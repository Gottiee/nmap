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

bool scan_all()
{
	printf("scan ALL\n");
	return (0); 
}

void scan(struct sockaddr_in *ping_addr, t_info *info)
{
	(void)ping_addr;
	(void)info;
	pcap_if_t *alldvsp = NULL;
	pcap_t *handle = NULL;

	// liste les devices et utilse le premier device utiliser la premiere interface trouvée (peut etre le secure ca)
	alldvsp = init_device();
	// creer un handler, qui va servir à ecouter sur l'interface seletionnée
	handle = init_handler(alldvsp->name);

	// switch (info->scan_type)
	// {
	// 	case (ALL):
	// 		scan_all();
	// 		break;
	// 	case(UDP):
	// 		scan_udp();
	// 		break;
	// 	case(SYN):
	// 		scan_syn();
	// 		break;
	// 	case(S_NULL):
	// 		scan_null();
	// 		break;
	// 	case(ACK):
	// 		scan_ack();
	// 		break;
	// 	case(XMAS):
	// 		scan_xmas();
	// 		break;
	// 	case(FIN):
	// 		scan_fin();
	// 		break;
	// 	default:
	// 		fatal_error("NANI\n");
	// 		break;
	// }

	pcap_freealldevs(alldvsp);
	pcap_close(handle);
}
