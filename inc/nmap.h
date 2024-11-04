#ifndef NMAP_H
#define NMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <bool.h>

#include "thread.h"
#include "error.h"
#include "file.h"
#include "handle_arg.h"
#include "network.h"

//	SCAN VALUES
#define ALL 0
#define SYN 1
#define NULL 2
#define ACK 4
#define FIN 8
#define XMAS 16
#define UDP 32

#define MAX_SCAN 65535

typdef struct 	info_t
{
	char	**hostnames;
	unsigned char	nb_thread;
	unsigned char	scans;
	unsigned int	
}				s_info;

#endif