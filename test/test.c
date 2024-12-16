#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

int main() {
	struct ifaddrs *ifaddr, *ifa;
	char ip[INET_ADDRSTRLEN];

	// Get the list of network interfaces
	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return EXIT_FAILURE;
	}

	// Loop through the list of interfaces
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		// Check for IPv4 addresses
		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;

			// Convert the address to a human-readable string
			if (inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip)) != NULL) {
				printf("Interface: %s\n", ifa->ifa_name);
				printf("IP Address: %s\n", ip);
			}
		}
	}

	// Free the memory allocated by getifaddrs
	freeifaddrs(ifaddr);

	return EXIT_SUCCESS;
}