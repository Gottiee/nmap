#ifndef NMAP_H
#define NMAP_H

#include "network.h"
typedef struct s_info
{
    int thread;
    int scan_type;
    t_info_port *port_info;
} t_info;

#include <stdio.h>
#include <stdlib.h>
#include "thread.h"
#include "error.h"
#include "file.h"
#include "handle_arg.h"
#include "icmp.h"

#endif