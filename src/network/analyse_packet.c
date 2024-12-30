#include "../../inc/nmap.h"


void	print_packet_raw( const u_char *packet )
{
	for (int i = 0; i < 60; i++)
	{
		printf("%.02x.", packet[i]);
	}
	printf("\n");
}

void	recv_tcp( const u_char *r_buf, t_scan_port *port, const uint8_t th_id, const uint8_t scan_type, t_host *host )
{
	(void) th_id;
	r_buf += 16;
	struct iphdr	*r_ip = (struct iphdr *)(r_buf);
	struct tcphdr	*r_tcp = (struct tcphdr *)(r_buf + (r_ip->ihl * 4));
	struct icmphdr	*r_icmp = (struct icmphdr *)(r_buf + (r_ip->ihl * 4));

	if (scan_type == SYN && r_ip->protocol == IPPROTO_ICMP)
	{
		if (r_icmp->type == 3)
		{
			if (r_icmp->code == 1 || r_icmp->code == 2 || r_icmp->code == 3 
				|| r_icmp->code == 9 || r_icmp->code == 10 || r_icmp->code == 13)
			{
				port->state[scan_type] = FILTERED;
			}
		}
	}
	else if (r_ip->protocol == IPPROTO_TCP)
	{
		if (scan_type == SYN && r_tcp->syn && r_tcp->ack)
		{
			port->state[scan_type] = OPEN;
			pthread_mutex_lock(&g_print_lock);
			host->open ++;
			pthread_mutex_unlock(&g_print_lock);
		}
		else if (r_tcp->rst)
		{
			if (scan_type == ACK)
				port->state[scan_type] = UNFILTERED;
			else
				port->state[scan_type] = CLOSE; 
		}
	}
	else
		port->state[scan_type] = CLOSE;
}

void	recv_udp( const u_char *r_buf, t_scan_port *port, const uint8_t th_id, const uint8_t scan_type, t_host *host )
{
	(void) th_id;
	r_buf += 16;
	struct iphdr	*r_ip = (struct iphdr *)(r_buf);
	struct icmphdr	*r_icmp = (struct icmphdr *)(r_buf + (r_ip->ihl * 4));

	if (r_ip->protocol == IPPROTO_ICMP)
	{
		if (r_icmp->type == 3)
		{
			if (r_icmp->code == 1 || r_icmp->code == 2
				|| r_icmp->code == 9 || r_icmp->code == 10 || r_icmp->code == 13)
			{
				port->state[scan_type] = FILTERED;
			}
			else if (r_icmp->code == 3)
				port->state[scan_type] = CLOSE;
		}
	}
	else
	{
		port->state[scan_type] = OPEN;
		pthread_mutex_lock(&g_print_lock);
		host->open ++;
		pthread_mutex_unlock(&g_print_lock);
	}
}

bool	handle_return_packet( const u_char *r_buf, t_scan_port *port, const uint8_t th_id, const uint8_t scan_type, t_host *host)
{
	(void) th_id;
	
	if (scan_type != UDP)
		recv_tcp(r_buf, port, th_id, scan_type, host);
	else
		recv_udp(r_buf, port, th_id, scan_type, host);
	return (0);
}
