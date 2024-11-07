#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

void packet_handler(u_char *args, struct pcap_pkthdr *header, u_char *packet)
{
    printf("NEW PACKET:\n");
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    printf("Total packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);

    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n");
        return;
    }
    tcp_header = packet + ethernet_header_length + ip_header_length;
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);

    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", payload);

    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }
    printf("----------------\n\n");
    return;
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) 
{
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}

void capture_packet(char *device)
{
    struct pcap_pkthdr packet_header;
    const u_char *packet;
    pcap_t *handle;
    int packet_count_limit = 1;
    int timeout_limit = 10000; /* In milliseconds */
    char error_buffer[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(device, BUFSIZ, packet_count_limit, timeout_limit, error_buffer);

    if (!handle)
    {
        printf("%s\n", error_buffer);
        exit(23);
    }

    // choper un packet
    // packet = pcap_next(handle, &packet_header);
    // if (packet == NULL)
    // {
    //     printf("no pakcet foudn\n");
    //     exit(2);
    // }
    // print_packet_info(packet, packet_header);

    pcap_loop(handle, 0, packet_handler, NULL);
}

void print_all_dev(pcap_if_t *alldvsp)
{
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct in_addr addr;

    printf("device = %s\n", alldvsp->name);
    if (pcap_lookupnet(alldvsp->name,&netp,&maskp,error_buffer))
    {
        printf("Error ?\n");
        exit(1);
    }
    addr.s_addr = netp;
    // verifie si netp est pas null
    printf("Ip: %s\n", inet_ntoa(addr));
    // verifier si maskp est pas null
    addr.s_addr = maskp;
    printf("Mask: %s\n", inet_ntoa(addr));
}

int main(void)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldvsp = NULL;

    /* Find a device */
    if (pcap_findalldevs(&alldvsp, error_buffer))
    {
        fprintf(stderr, "%s\n", error_buffer);
        exit(1);
    }
    print_all_dev(alldvsp);
    capture_packet(alldvsp->name);

    pcap_freealldevs(alldvsp);
}