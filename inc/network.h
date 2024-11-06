#ifndef NETWORK_H
#define NETWORK_H

#define OPEN 1
#define CLOSE 2
#define FILTERED 3
#include <stdbool.h>

typedef struct s_scan_port
{
    int port_nbr;
    char *service;
    int state[7];
} t_scan_port;

typedef struct s_info_port
{
    int nbr_of_port_scan;
    int to_scan[1024];
} t_info_port;

typedef struct s_host
{
    struct host *next;
    t_scan_port port_tab[1024];
} t_host;

bool dns_lookup(char *input_domain, struct sockaddr_in *ping_addr);

#endif