#ifndef ICMP_H
#define ICMP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <sys/time.h>
#include <stdbool.h>
#define PING_PKT_S 64

typedef struct s_ping_pkt
{
    struct icmphdr hdr;
    char msg[PING_PKT_S - sizeof(struct icmphdr)];
}t_ping_pkt;

typedef struct s_icmp_data
{
    struct sockaddr_in *ping_addr;
    int ttl;
    int sockfd;
    t_ping_pkt pckt;
    int id;
    int recv_timeout;
} t_icmp_data;

bool ping_ip(struct sockaddr_in *ping_address);

#endif