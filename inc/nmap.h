#ifndef NMAP_H
#define NMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h> 
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include "handle_arg.h"
#include "thread.h"
#include "error.h"
#include "file.h"
#include "network.h"

//	SCAN VALUES
#define ALL 0
#define SYN 1
#define S_NULL 2
#define ACK 4
#define FIN 8
#define XMAS 16
#define UDP 32

#define MAX_SCAN 65535

typedef struct 	info_t
{
	char	**hostnames;
	uint8_t	nb_thread;
	uint8_t	scans;
	unsigned short	ports[2];
}				s_info;

#endif