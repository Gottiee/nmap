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


bool	handle_return_packet( const u_char *r_buf, t_scan_port *port, const uint8_t th_id )
{
	// pthread_mutex_lock(&g_print_lock);printf("(%d) In handle_return_packet()\n", th_id);pthread_mutex_unlock(&g_print_lock);
	tests_r_packet(r_buf, th_id);
	
	r_buf += 16;
	struct iphdr	*r_ip = (struct iphdr *)(r_buf);
	struct tcphdr	*r_tcp = (struct tcphdr *)(r_buf + (r_ip->ihl * 4));
	struct icmphdr	*r_icmp = (struct icmphdr *)(r_buf + (r_ip->ihl * 4));
	// struct in_addr	s_addr;
	// s_addr.s_addr = r_ip->saddr;
	(void) r_ip; (void) r_tcp; (void) port;
	if (r_ip->protocol == IPPROTO_ICMP)
	{
		//	ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
		if (r_icmp->type == 3)
		{
			if (r_icmp->code == 1 || r_icmp->code == 2 || r_icmp->code == 3 
				|| r_icmp->code == 9 || r_icmp->code == 10 || r_icmp->code == 13)
			{
				//	STATE = FILTERED
				// pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn: handle return: icmp code %d type %d received\n", th_id, r_icmp->type, r_icmp->code);pthread_mutex_unlock(&g_print_lock);
				port->state = FILTERED;
			}
		}
		else
		{
			// pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn: handle return: icmp type %d received => error\n", th_id, r_icmp->type);pthread_mutex_unlock(&g_print_lock);
			return (1);
		}
	}
	else if (r_ip->protocol == IPPROTO_TCP)
	{
		// print_packet_raw(r_buf);
		pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn(): recv TCP ", th_id);pthread_mutex_unlock(&g_print_lock);
		if (r_tcp->syn)
		{
			// pthread_mutex_lock(&g_print_lock);printf("(%d)flag SYN ", th_id);pthread_mutex_unlock(&g_print_lock);
			//	STATE = OPEN
			port->state = OPEN;
		}
		if (r_tcp->ack)
		{
			// pthread_mutex_lock(&g_print_lock);printf("(%d)flag ACK ", th_id);pthread_mutex_unlock(&g_print_lock);
		}
		if (r_tcp->rst)
		{
			// pthread_mutex_lock(&g_print_lock);printf("(%d)flag RST ", th_id);pthread_mutex_unlock(&g_print_lock);
			//	STATE = CLOSED
			port->state = CLOSE;
		}
		printf("\n");
	}
	else
	{
		// pthread_mutex_lock(&g_print_lock);printf("(%d) scan_syn(): recv protocol %d\n", th_id, r_ip->protocol);pthread_mutex_unlock(&g_print_lock);
			// STATE = CLOSED
		// print_packet_raw(r_buf);
		port->state = CLOSE;
	}
	// pthread_mutex_lock(&g_print_lock);printf("(%s)\n", inet_ntoa(s_addr));pthread_mutex_unlock(&g_print_lock);
	return (0);
}
