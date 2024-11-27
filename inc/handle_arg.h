#ifndef ARG_H
#define ARG_H

#include <stdint.h>


typedef struct s_info t_info;
typedef struct s_info_port t_info_port;

char	**handle_arg( int argc, char ***argv, t_info *info );


#endif