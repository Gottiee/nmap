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

    // boucler sur les host
    if (info.thread > 0)
        create_thread(&info, host);
    free(host);
}