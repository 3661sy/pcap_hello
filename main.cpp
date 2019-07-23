#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#define ETH_ALEN	6
#define ETHERTYPE_IP	0x0800
#define ETHERTYPE_ARP	0x0806

struct ether_header
{
	uint8_t dst[ETH_ALEN];
	uint8_t src[ETH_ALEN];
	uint16_t ether_type;
} __attribute__ ((__packed__));

void usage()
{
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open divece %s: %s\n", dev, errbuf);
		return -1;
	}

	while (true)
	{
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		const ether_header *eth = (ether_header *)packet;
		printf("%u bytes capturned\n", header->caplen);
		printf("%02X:%02X:%02X:%02X:%02X:%02x\n", eth->src[0], eth->src[1], eth->src[2], eth->src[3],eth->src[4], eth->src[5]);
		printf("%02X:%02X:%02X:%02X:%02X:%02x\n", eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3],eth->dst[4], eth->dst[5]);
		if(ntohs(eth->ether_type) == 0x0806)
			printf("ARP type\n");
		if(ntohs(eth->ether_type) == 0x0800)
			printf("IP type\n");
	}

	pcap_close(handle);
	return 0;
}

