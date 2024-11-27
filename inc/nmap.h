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

typedef struct s_info t_info;

#include "icmp.h"
#include "network.h"
#include "handle_arg.h"
#include "thread.h"
#include "error.h"
#include "file.h"
#include "utils.h"


//	SCAN VALUES
#define ALL 0
#define SYN 1
#define S_NULL 2
#define ACK 3
#define FIN 4
#define XMAS 5
#define UDP 6

#define MAX_SCAN 65535

typedef struct s_info
{
	char	**hostnames;
	int nb_thread;
	int scan_type;
	int	nb_host_ping;
	int	nb_host_ping_success;
	uint16_t	first_port;
	uint16_t	port_range;
	t_host *start_host;
	struct timeval time_start;
	struct sockaddr_in	ping_addr;
} t_info;

//	PRINT.C
void	super_print( t_host *host, t_info *info );

#endif