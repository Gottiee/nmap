#include "../inc/nmap.h"

void fake_init_info(char **argv, int argc, t_info_port *port_info)
{
    for (int i = 0; i < argc - 1; i++)
        port_info->to_scan[i] = atoi(argv[i + 1]);
    port_info->nbr_of_port_scan = argc - 1;
    printf("-> %d port to scan\n", port_info->nbr_of_port_scan);
}

int main(int argc, char **argv)
{
    t_info info;
    t_info_port port_info;
    t_host *host;

    host = malloc(sizeof(t_host));

    info.thread = 3;
    fake_init_info(argv, argc, &port_info);
    info.port_info = &port_info;

    struct sockaddr_in ping_addr;

    // boucler sur les host / IP
    // pour chaque remplire ping_addr
    // l'envoyer a ping_ip
    // reponds True si le ping a fonctionné

    dns_lookup("google.com", &ping_addr);
    if (ping_ip(&ping_addr))
        printf("Pinging goolgle worked\n");
    else
        printf("Pinging Google.com failed\n");
    if (info.thread > 0)
        threading_scan_port(&info, host);
    free(host);
}