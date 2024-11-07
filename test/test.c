#include <stdio.h>
#include <pcap/pcap.h>

int	main( int argc, char **argv )
{
	char	errbuf[PCAP_ERRBUF_SIZE] = {0};

	if (pcap_init( PCAP_MMAP_32BIT, errbuf) == PCAP_ERROR)
	{
		printf("Error\n");
	}
	else
	{
		printf("OK");
	}
	return (0);
}