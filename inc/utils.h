#ifndef UTILS_H
#define UTILS_H

double time_till_start(struct timeval *start);
t_host *init_host_list(char *name, t_info *info);
t_host *add_host_list(char *name, t_host *start, t_info *info);
void free_host_list(t_host *start);
void	free_host_tab_str( char **hostnames );
bool	return_error( char *err_mess );
void get_local_ip( char *buffer, struct sockaddr_in *tmp_ip );
char  *return_service_udp(int port);
char *return_service_tcp(int port);
int    ft_nblen(int nb);
char		*ft_itoa(int num);

#endif