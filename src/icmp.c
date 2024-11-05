#include "../inc/nmap.h"

unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

bool fill_sockaddr_in(t_icmp_data *icmp_data, char *target) 
{
    ft_memset(&icmp_data->ping_addr, 0, sizeof(struct sockaddr_in));

    // tcheck si c'est une address ipv4
    if (inet_pton(AF_INET, target, &(icmp_data->ping_addr.sin_addr)) == 1) {
        icmp_data->ping_addr.sin_family = AF_INET;
        icmp_data->ping_addr.sin_port = htons(0);
        ft_strncpy(icmp_data->ip, target, 1024);
        return true;
    }
    if (!dns_lookup(target, icmp_data->ip, &icmp_data->ping_addr))
        fatal_error("traceroute: unknown host\n");
    ft_strncpy(icmp_data->domain, target, 499);
    return true;
}

int socket_creation()
{
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd == -1)
        return -1;
    return sockfd;
}

void init_icmp_data(t_icmp_data *icmp_data)
{
    ft_memset(icmp_data->domain, 0, 500);
    ft_memset(icmp_data->ip, 0, 1025);
    icmp_data->ttl = 1;
    icmp_data->hope = 64;
    icmp_data->queries = 3;
    icmp_data->sockfd = socket_creation();
    if (icmp_data->sockfd == -1)
        fatal_error("traceroute: Lacking privilege for icmp socket.\n");
    icmp_data->sequence = 0;
    icmp_data->id = getpid();
    icmp_data->recv_timeout = 1;
}

void fill_icmp(t_ping_pkt *pckt, int sequence)
{
    long unsigned int i;

    bzero(pckt, sizeof(t_ping_pkt));
    pckt->hdr.type = ICMP_ECHO;
    pckt->hdr.un.echo.id = getpid();
    for (i = 0; i < sizeof(pckt->msg) - 1; i++)
        pckt->msg[i] = i + '0';
    pckt->msg[i] = 0;
    pckt->hdr.un.echo.sequence = htons(sequence);
    pckt->hdr.checksum = checksum(pckt,sizeof((*pckt)));
}

void send_ping(t_icmp_data *icmp_data)
{
    fill_icmp(&icmp_data->pckt, icmp_data->sequence);
    gettimeofday(&icmp_data->time_loop_start, NULL);
    if (sendto(icmp_data->sockfd, &icmp_data->pckt, sizeof(t_ping_pkt), 0, (struct sockaddr *)&icmp_data->ping_addr, sizeof(icmp_data->ping_addr)) <= 0 )
        fatal_perror("Packet Sending Failed");
}

void setup_socket(t_icmp_data *icmp_data, int ttl)
{
    struct timeval tv_out;
    tv_out.tv_sec = icmp_data->recv_timeout;
    tv_out.tv_usec = 0;
    
    if (setsockopt(icmp_data->sockfd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0)
        fatal_perror("Error: setup ttl to socket");
    if (setsockopt(icmp_data->sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof(tv_out)) != 0)
        fatal_perror("Error: setup timeout socket");
}

double receive_ping(t_icmp_data *icmp_data, bool *finish, char *ip)
{
    char rbuffer[128];

    if (recvfrom(icmp_data->sockfd, rbuffer, sizeof(rbuffer), 0, NULL, NULL) <= 0)
        return NO_PKT;
    struct icmphdr *recv_hdr = (struct icmphdr *)(rbuffer + sizeof(struct iphdr));
    struct iphdr *recv_ip_header = (struct iphdr *)(rbuffer);
    // si il lit une erreur verifier que l'erreur est pour moi si non return
    if (recv_hdr->type == ICMP_TIME_EXCEEDED || recv_hdr->type == ICMP_DEST_UNREACH)
    {
        struct iphdr *error_ip = (struct iphdr *)(rbuffer + sizeof(struct icmphdr) + sizeof(struct iphdr));
        struct icmphdr *error_icmp = (struct icmphdr *)(rbuffer + sizeof(struct icmphdr) + sizeof(struct iphdr) + (error_ip->ihl * 4));
        if (!analyse_error(error_icmp, icmp_data))
            return WRONG_PKT;
        retrieve_ip(recv_ip_header, ip);
        return get_ms_response(icmp_data);
    }
    // le paquet m'est pas destine, ou la loopback me troll
    else if (recv_hdr->un.echo.id != icmp_data->id || recv_hdr->type == 8)
        return WRONG_PKT;
    if ((recv_hdr->type == 0 && recv_hdr->code == 0))
    {
        retrieve_ip(recv_ip_header, ip);
        *finish = true;
        return get_ms_response(icmp_data);
    }
    return NO_PKT;
}

void ping_ip(int *ip)
{

    // iterer sur le tableau d'ip pour voir si y'a une string vide
    // je recois un char ou un int ? 
    // creer la structure t_icmp_data
    // la remplire
    // ping
    // gerer avec les thread si y'en a
    // modifier le tableau selon ceux qui ont repondu au ping

    t_icmp_data icmp_data;
    char *host;

    init_icmp_data(&icmp_data);
    host = handle_args(&argv[1], &icmp_data);
    if (!host)
        missing_host_operand();
    check_arg(&icmp_data);
    fill_sockaddr_in(&icmp_data, host);
    print_header(&icmp_data);
    ttl_loop(&icmp_data);
    close(icmp_data.sockfd);
}