#ifndef UTILS_H
#define UTILS_H

double time_till_start(struct timeval *start);
t_host *init_host_list(char *name);
t_host *add_host_list(char *name, t_host *start);

#endif