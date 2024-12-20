#ifndef NMAP_H
#define NMAP_H

typedef struct s_info t_info;

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>

#include <ifaddrs.h>

typedef struct s_info t_info;

#include "icmp.h"
#include "network.h"
#include "handle_arg.h"
#include "thread.h"
#include "error.h"
#include "file.h"
#include "utils.h"
#include "colors.h"

//	SCAN VALUES
#define SYN 0
#define S_NULL 1
#define ACK 2
#define FIN 3
#define XMAS 4
#define UDP 5
#define ALL 6

#define NB_MAX_SCAN 6

#define MAX_SCAN 65535
#define IPADDR_STRLEN 15
#define MAX_FILTER_LEN 43
#define INTERFACE_MAX_LEN 15

extern t_info *g_info;

typedef struct	s_opt
{
	bool	ping;
	bool	random;
	char	*interface;
	uint32_t	ttl;
	int	nb_retries;
}				t_opt;

typedef struct	s_info
{
	char	**hostnames;
	char	*device;
	uint16_t	first_port;
	uint16_t	port_range;
	int nb_thread;
	int scan_type[NB_MAX_SCAN];
	int	nb_host_ping;
	int	nb_host_ping_success;
	t_host *start_host;
	t_opt	options;
	struct timeval time_start;
	struct sockaddr_in	ping_addr;
	struct in_addr	ip_src;
} t_info;

//	PRINT.C
void	super_print( t_host *host, t_info *info );
void	print_usage( void );

#endif