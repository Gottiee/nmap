#ifndef ARG_H
#define ARG_H

#include <stdint.h>


typedef struct s_info_port
{
	int nbr_of_port_scan;
	unsigned short to_scan[1025];
} t_info_port;

typedef struct s_scan_port
{
	int port_nbr;
	char *service;
	int state;
} t_scan_port;

typedef struct s_host
{
	char	*name;
	struct s_scan_port port_tab[1025];
	struct s_host *next;
} t_host;

typedef struct 	info_t
{
	char	**hostnames;
	uint8_t	nb_thread;
	uint8_t	scans;
	unsigned short	ports[2];
}				s_info;


char	**handle_arg( int argc, char ***argv, s_info *info, t_info_port *info_ports );


#endif