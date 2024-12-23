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

int socket_creation()
{
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd == -1)
        return -1;
    return sockfd;
}

void init_icmp_data(t_icmp_data *data, struct sockaddr_in *ping_address)
{
    data->ttl = g_info->options.ttl;
    data->sockfd = socket_creation();
    if (data->sockfd == -1)
        fatal_error("ft_nmap: Lacking privilege for icmp socket.\n");
    data->id = getpid();
    data->recv_timeout = 1;
    data->ping_addr = ping_address;
}

void fill_icmp(t_ping_pkt *pckt)
{
    long unsigned int i;

    bzero(pckt, sizeof(t_ping_pkt));
    pckt->hdr.type = ICMP_ECHO;
    pckt->hdr.un.echo.id = getpid();
    for (i = 0; i < sizeof(pckt->msg) - 1; i++)
        pckt->msg[i] = i + '0';
    pckt->msg[i] = 0;
    pckt->hdr.un.echo.sequence = htons(0);
    pckt->hdr.checksum = checksum(pckt,sizeof((*pckt)));
}

void send_ping(t_icmp_data *data)
{
    fill_icmp(&data->pckt);
    if (sendto(data->sockfd, &data->pckt, sizeof(t_ping_pkt), 0, (struct sockaddr *)data->ping_addr, sizeof(struct sockaddr)) <= 0 )
        fatal_perror("Packet Sending Failed");
}

void setup_socket(t_icmp_data *data)
{
    struct timeval tv_out; (void) tv_out;
    tv_out.tv_sec = data->recv_timeout;
    tv_out.tv_usec = 0;
    
    if (setsockopt(data->sockfd, SOL_IP, IP_TTL, &data->ttl, sizeof(int)) != 0)
        fatal_perror("Error: setup ttl to socket");
    if (setsockopt(data->sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof(tv_out)) != 0)
        fatal_perror("Error: setup timeout socket");
}

bool receive_ping(t_icmp_data *data)
{
    char rbuffer[128];

    if (recvfrom(data->sockfd, rbuffer, sizeof(rbuffer), 0, NULL, NULL) <= 0)
        return false;
    struct icmphdr *recv_hdr = (struct icmphdr *)(rbuffer + sizeof(struct iphdr));
    while (recv_hdr->un.echo.id != data->id || recv_hdr->type == 8)
    {
        if (recvfrom(data->sockfd, rbuffer, sizeof(rbuffer), 0, NULL, NULL) <= 0)
            return false;

    }
    if ((recv_hdr->type == 0 && recv_hdr->code == 0))
        return true;
    return false;
}

bool ping_ip(struct sockaddr_in *ping_address)
{
    t_icmp_data data;
    bool ret;
    init_icmp_data(&data, ping_address); 
    setup_socket(&data);
    send_ping(&data);
    ret = receive_ping(&data);
    close(data.sockfd);
    return ret;
}