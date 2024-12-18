#include "../../inc/nmap.h"


void	print_packet_raw( const u_char *packet )
{
	for (int i = 0; i < 60; i++)
	{
		printf("%.02x.", packet[i]);
	}
	printf("\n");
}

void	tests_r_packet( const u_char r_buf[IP_MAXPACKET], const uint8_t th_id )
{
	const struct iphdr	*ip_h = (const struct iphdr *) r_buf;
	const struct tcphdr	*tcp_h = NULL;
	const struct icmphdr	*icmp_h = NULL;

	if (ip_h->protocol == IPPROTO_TCP)
	{
		// TCP SYN/ACK response => open
		// TCP RST response	=> closed
		tcp_h = (const struct tcphdr *) (r_buf + sizeof(struct iphdr));
		if ((tcp_h->syn != 1 || tcp_h->ack != 1) && tcp_h->rst != 1)
			printf(RED "(%d) tcp wrong flags\n" RESET, th_id);
		else
			printf(GREEN "(%d) tcmp packet OK\n" RESET, th_id);
	}
	else if (ip_h->protocol == IPPROTO_ICMP)
	{
		// ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13) => filtered
		icmp_h = (const struct icmphdr *) (r_buf + sizeof(struct iphdr));
		if (icmp_h->type != 3)
			printf(RED "(%d) icmp wrong type (Received: %d\n" RESET, th_id, icmp_h->type);
		else if (icmp_h->code != 1 && icmp_h->code != 2 && icmp_h->code != 3 && icmp_h->code != 9 && 
				icmp_h->code != 10 && icmp_h->code != 13)
			printf(RED "(%d) icmp wrong code (Received: %d)\n" RESET, th_id, icmp_h->code);
		else
			printf(GREEN "(%d) icmp packet OK" RESET, th_id);
	}
	return ;
}

void	recv_tcp( const u_char *r_buf, t_scan_port *port, const uint8_t th_id, const uint8_t scan_type, t_host *host )
{
	r_buf += 16;
	struct iphdr	*r_ip = (struct iphdr *)(r_buf);
	struct tcphdr	*r_tcp = (struct tcphdr *)(r_buf + (r_ip->ihl * 4));
	struct icmphdr	*r_icmp = (struct icmphdr *)(r_buf + (r_ip->ihl * 4));

	if (scan_type == SYN && r_ip->protocol == IPPROTO_ICMP)
	{
		pthread_mutex_lock(&g_print_lock);
		printf("(%d) recv_tcp: handle_return: scap_type == %d | protocol == ICMP | type == %d | code == %d\n", 
				th_id, scan_type, r_icmp->type, r_icmp->code);pthread_mutex_unlock(&g_print_lock);
		//	ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
		if (r_icmp->type == 3)
		{
			if (r_icmp->code == 1 || r_icmp->code == 2 || r_icmp->code == 3 
				|| r_icmp->code == 9 || r_icmp->code == 10 || r_icmp->code == 13)
			{
				// pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn: handle return: icmp code %d type %d received\n", th_id, r_icmp->type, r_icmp->code);pthread_mutex_unlock(&g_print_lock);
				port->state[scan_type] = FILTERED;
			}
		}
		else
		{
			pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn: handle return: icmp type %d received => error\n", th_id, r_icmp->type);pthread_mutex_unlock(&g_print_lock);
		}
	}
	else if (r_ip->protocol == IPPROTO_TCP)
	{
		// print_packet_raw(r_buf);
		// pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn(): recv TCP ", th_id);pthread_mutex_unlock(&g_print_lock);
	pthread_mutex_lock(&g_print_lock);
	printf("(%d) recv_tcp: handle return: scan_type == %d | protocol == TCP | syn == %d | ack == %d | rst == %d\n", 
			th_id, scan_type, r_tcp->syn, r_tcp->ack, r_tcp->rst);pthread_mutex_unlock(&g_print_lock);
		if (scan_type == SYN && r_tcp->syn && r_tcp->ack)
		{
			// pthread_mutex_lock(&g_print_lock);printf("(%d)flag SYN ", th_id);pthread_mutex_unlock(&g_print_lock);
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
		printf("\n");
	}
	else
	{
		// pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn(): recv protocol %d\n", th_id, r_ip->protocol);pthread_mutex_unlock(&g_print_lock);
			// STATE = CLOSED
		// print_packet_raw(r_buf);
		port->state[scan_type] = CLOSE;
	}
}

bool	handle_return_packet( const u_char *r_buf, t_scan_port *port, const uint8_t th_id, const uint8_t scan_type, t_host *host)
{
	// pthread_mutex_lock(&g_print_lock);printf("(%d) In handle_return_packet()\n", th_id);pthread_mutex_unlock(&g_print_lock);
	tests_r_packet(r_buf, th_id);
	
	// pthread_mutex_lock(&g_print_lock);printf("(%s)\n", inet_ntoa(s_addr));pthread_mutex_unlock(&g_print_lock);
	if (scan_type != UDP)
		recv_tcp(r_buf, port, th_id, scan_type, host);
	// else
		// recv_udp(r_buf, port, th_id, scan_type);
	return (0);
}
