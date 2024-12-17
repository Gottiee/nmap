#include "../inc/nmap.h"

bool	return_error( char *err_mess )
{
	perror(err_mess);
	return (1);
}

double time_till_start(struct timeval *start)
{
	struct timeval end;

    gettimeofday(&end, NULL);
    return (end.tv_sec - start->tv_sec) + (end.tv_usec - start->tv_usec) / 1e6;
}

t_host *add_host_list(char *name, t_host *start, t_info *info)
{
    t_host *new = malloc(sizeof(t_host));
    if (!new)
        fatal_perror("Malloc error \"t_host *new\"");

    while (start->next)
    {
        start->next = new;
        new->next = NULL;
        new->name = name;
		start->port_tab = malloc(sizeof(t_scan_port) * (info->port_range));
		if (start->port_tab == NULL)
			fatal_perror("Malloc error \"t_host *new\"");
    }
    return new;
}

t_host *init_host_list(char *name, t_info *info)
{
    t_host *start = malloc(sizeof(t_host));
    if (!start)
        fatal_perror("Error malloc \"t_host start\"");
    start->next = NULL;
    start->name = name;
	// printf("port_range == %d\n", info->port_range);
	start->port_tab = malloc(sizeof(t_scan_port) * (info->port_range));
	if (start->port_tab == NULL)
			fatal_perror("Malloc error \"t_host *new\"");
    return start;
}

void free_host_list(t_host *start)
{
    t_host *tmp = NULL;
    while (start)
    {
        tmp = start;
		free(start->port_tab);
        start = start->next;
        free(tmp);
    }
}

// void	get_local_ip( char *buffer )
// {
//     struct addrinfo hints, *res;
//     int sock;
//     struct sockaddr_in addr;
//     socklen_t addr_len = sizeof(addr);

//     // Create a temporary socket
//     memset(&hints, 0, sizeof(hints));
//     hints.ai_family = AF_INET;
//     hints.ai_socktype = SOCK_DGRAM;

//     // Connect to a public IP to infer the local IP
//     getaddrinfo("8.8.8.8", "53", &hints, &res); // Google's DNS server
//     sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
//     connect(sock, res->ai_addr, res->ai_addrlen);
//     getsockname(sock, (struct sockaddr *)&addr, &addr_len);
//     inet_ntop(AF_INET, &addr.sin_addr, buffer, INET_ADDRSTRLEN);

//     close(sock);
//     freeaddrinfo(res);
// }

void get_local_ip( char *buffer, struct sockaddr_in *tmp_ip )
{
	struct ifaddrs *ifaddr, *ifa;
	char ip[INET_ADDRSTRLEN] = {0};

	// Get the list of network interfaces
	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
	}

	// Loop through the list of interfaces
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		// Check for IPv4 addresses
		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;

			// Convert the address to a human-readable string
			if (inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip)) != NULL)
			{
				memcpy(&tmp_ip->sin_addr, &addr->sin_addr, sizeof(struct sockaddr_in));
				// printf("Interface: %s\n", ifa->ifa_name);
				if (strcmp(ifa->ifa_name, "enp0s3") == 0)
				{
					printf("copying >> ");
					printf("IP Address: %s\n", ip);
					memcpy(buffer, ip, sizeof(ip));
				}
			}
		}
	}

	// Free the memory allocated by getifaddrs
	freeifaddrs(ifaddr);
}
