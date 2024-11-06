#ifndef NMAP_H
#define NMAP_H

typedef struct s_info t_info;

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include "icmp.h"
#include "network.h"
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>

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
#define ACK 4
#define FIN 8
#define XMAS 16
#define UDP 32

#define MAX_SCAN 65535

typedef struct s_info
{
	char	**hostnames;
	int nb_thread;
	int scan_type;
	t_info_port *port_info;
} t_info;


#endif