#include "../../inc/nmap.h"

bool dns_lookup(char *input_domain, struct sockaddr_in *ping_addr)
{
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if ((getaddrinfo(input_domain, NULL, &hints, &res)) != 0)
        return false;
    ping_addr->sin_family = AF_INET;
    ping_addr->sin_port = htons(0);
    ping_addr->sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return true;
}

bool fill_sockaddr_in(char *target, struct sockaddr_in *ping_addr) 
{
    memset(ping_addr, 0, sizeof(struct sockaddr_in));

    // tcheck si c'est une address ipv4
    if (inet_pton(AF_INET, target, &ping_addr->sin_addr) == 1) {
        ping_addr->sin_family = AF_INET;
        ping_addr->sin_port = htons(0);
        return true;
    }
    if (!dns_lookup(target, ping_addr))
        return false;
    return true;
}