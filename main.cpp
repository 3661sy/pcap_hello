#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#define ETH_ALEN	6
#define ETHERTYPE_IP	0x0800
#define ETHERTYPE_ARP	0x0806

struct ip_addr
{
	uint8_t a;
	uint8_t b;
	uint8_t c;
	uint8_t d;
};

struct ip_header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t ip_hl : 4;
	uint32_t ip_v : 4;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
	uint32_t ip_v : 4;
	uint32_t ip_hl : 4;
#endif
	uint8_t ip_tos;
	uint16_t ip_len;
	uint16_t ip_id;
	uint16_t ip_off;
#define	IP_RF	0x8000
#define	IP_DF	0x4000
#define IP_MF	0x2000
#define	IP_OFFMASK	0x1fff
	uint8_t ip_ttl;
	uint8_t ip_p;
	uint16_t ip_sum;
	ip_addr ip_src;
	ip_addr ip_dst;
};

typedef uint32_t tcp_seq;

struct tcp_header
{
	__extension__ union
	{
		struct
		{
	uint16_t th_sport;
	uint16_t th_dport;
	tcp_seq th_seq;
	tcp_seq th_ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t th_x2:4;
	uint8_t th_off:4;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t th_off:4;
	uint8_t th_x2:4;
#endif
	uint8_t th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
	uint16_t th_win;
	uint16_t th_sum;
	uint16_t th_urp;
		};
		struct
		{
		uint16_t source;
		uint16_t dest;
		uint32_t seq;
		uint32_t tack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint16_t res1:4;
		uint16_t doff:4;
		uint16_t fin:1;
		uint16_t syn:1;
		uint16_t rst:1;
		uint16_t psh:1;
		uint16_t ack:1;
		uint16_t urg:1;
		uint16_t res2:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
		uint16_t doff:4;
		uint16_t res1:4;
		uint16_t res2:2;
		uint16_t urg:1;
		uint16_t ack:1;
		uint16_t psh:1;
		uint16_t rst:1;
		uint16_t syn:1;
		uint16_t fin:1;
#else
#error "Adjust your <bits/endian.h> defines"
# endif
		uint16_t window;
		uint16_t check;
		uint16_t urg_ptr;
		};
	};
};

struct udp_header
{
#ifndef	_UDP_HEADER
	uint16_t src;
	uint16_t dst;
	uint16_t len;
	uint16_t check;

#define	UDP_CORK	1
#define	UDP_UNCAP	100
#define	UDP_NO_CHECK6_TX	101
#define	UDP_NO_CHECK6_RX	102
#define UDP_SEGMENT	103
#define	GRO	104
#define UDP_ENCAP_ESPINUDP_NON_IKE	1
#define UDP_ENCAP_ESPINUDP	2
#define UDP_ENCAP_L2PINUDP	3
#define UDP_ENCAP_GTP0	4
#define	UDP_ENCAP_GTP1U	5
#define UDP_ENCAP_RXRPC	6

#endif
};



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
		const ip_header *ip = (ip_header *)(packet + sizeof(ether_header));
		const tcp_header *tcp = (tcp_header *)(packet + sizeof(ether_header)+sizeof(ip_header));
		const udp_header *udp = (udp_header *)(packet + sizeof(ether_header)+sizeof(ip_header));

		u_char* data = (u_char *)(packet + sizeof(ether_header) + ip->ip_hl + tcp->th_off);
		uint32_t tcp_size = (ntohs(ip->ip_len) - ((ip->ip_hl + tcp->th_off) * 4));

		printf("%u byte captured\n", header->caplen);
		printf("%02X:%02X:%02X:%02X:%02X:%02x\n", eth->src[0], eth->src[1], eth->src[2], eth->src[3],eth->src[4], eth->src[5]);
		printf("%02X:%02X:%02X:%02X:%02X:%02x\n", eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3],eth->dst[4], eth->dst[5]);
	
		if(ntohs(eth->ether_type) == 0x0806)
			printf("ARP type\n");
		if(ntohs(eth->ether_type) == 0x0800) 
		{
			printf("IP type\n");
			printf("IP src: %d.%d.%d.%d\n",ip->ip_src.a, ip->ip_src.b, ip->ip_src.c, ip->ip_src.d);
			printf("IP dst: %d.%d.%d.%d\n",ip->ip_dst.a, ip->ip_dst.b, ip->ip_dst.c, ip->ip_dst.d);
		}

		if(ip->ip_p == 6)
		{
			printf("TCP src port: %d\n", ntohs(tcp->source));
			printf("TCP dst port: %d\n", ntohs(tcp->dest));

			for(int i = 0; i < tcp_size; i++)
			{
				printf("%02X ", data[i]);
				if(i % 8 == 0 && i % 16 == 0)
					printf("\n\n");
			}
			printf("\n");
		}

		if(ip->ip_p == 17)
		{
			printf("UDP src port: %d\n", ntohs(udp->src));
			printf("UDP dst port: %d\n", ntohs(udp->dst));
		}
					
		
	}

	pcap_close(handle);
	return 0;
}

