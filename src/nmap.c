#include "../inc/nmap.h"

void	init_values( t_info *info )
{
	info->hostnames = NULL;
	info->nb_thread = 0;
}

int main( int argc, char **argv )
{
    t_info info;
	t_info_port	info_ports;
    // t_host *host = NULL;
    // struct sockaddr_in ping_addr;
    // host = malloc(sizeof(t_host));
	// if (host == NULL)
	// {
	// 	perror("host malloc");
	// 	exit (1);
	// }

    info.port_info = &info_ports;

    // boucler sur les host / IP
    // pour chaque remplire ping_addr
    // l'envoyer a ping_ip
    // reponds True si le ping a fonctionné
	init_values(&info);
	info.hostnames = handle_arg(argc, &argv, &info, &info_ports);
	if (info.hostnames == NULL)
		exit (2);

	// for (unsigned short i = 0; i < info_ports.nbr_of_port_scan; i++)
	// 	printf("info_ports.to_scan[%d] == %hu\n", i, info_ports.to_scan[i]);

	// dns_lookup("google.com", &ping_addr);
	// if (ping_ip(&ping_addr))
	// 	printf("Pinging goolgle worked\n");
	// else
	// 	printf("Pinging Google.com failed\n");
	// if (info.nb_thread > 0)
	// 	threading_scan_port(&info, host);
	// free(host);
	
	for (size_t i = 0; info.hostnames[i] != NULL; i++)
		free(info.hostnames[i]);
	free(info.hostnames);
	return(0);
}