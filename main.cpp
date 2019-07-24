#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "protocol/all.h"
#include "packet.h"

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
		int packetIndex = 0;
		struct pcap_pkthdr* header; //packet
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		const ether_header *eth = (ether_header *)packet; //ethernet packet
		packetIndex += sizeof(ether_header);
		//packet capture output
		printf("%u byte captured\n", header->caplen);
	
		if(ntohs(eth->ether_type) == 0x0806)
		{	
			const arp_header *arp = (arp_header *)(packet + packetIndex);
			packetIndex += sizeof(arp_header);
			printf("ARP type\n");
			printf("Sender MAC addr: ");
			printMACAddress(arp->sender_mac);
		    printf("Target MAC addr: ");
			printMACAddress(arp->target_mac);
			printf("Sender IP: ");
			printIPAddress(arp->sender_ip);
			printf("Target IP: ");
			printIPAddress(arp->target_ip);

		}
		if(ntohs(eth->ether_type) == 0x0800) 
		{
			const ip_header *ip = (ip_header *)(packet + packetIndex); //ip header
			packetIndex += sizeof(ip_header);
			printf("IP type\n");
			printf("IP src: %d.%d.%d.%d\n",ip->ip_src.a, ip->ip_src.b, ip->ip_src.c, ip->ip_src.d);
			printf("IP dst: %d.%d.%d.%d\n",ip->ip_dst.a, ip->ip_dst.b, ip->ip_dst.c, ip->ip_dst.d);

			 if(ip->ip_p == 6) //tcp
               		 {
                        	const tcp_header *tcp = (tcp_header *)(packet + sizeof(ether_header)+sizeof(ip_header)); //tcp header
                       		 u_char* data = (u_char *)(packet + sizeof(ether_header) + ip->ip_hl + tcp->th_off); //tcp data
                       		 uint32_t tcp_size = (ntohs(ip->ip_len) - ((ip->ip_hl + tcp->th_off) * 4));
                       		 printf("TCP src port: %d\n", ntohs(tcp->source));
                       		 printf("TCP dst port: %d\n", ntohs(tcp->dest));

                       		 for(int i = 0; i < tcp_size; i++)
                       		 {
                               		 printf("%02X ", data[i]);
                               		 if(i % 8 == 0 && i % 16 == 0)
                                       	 printf("\n\n");
                       		 }
               		 }

               		 if(ip->ip_p == 17) //udp
               		 {
                       		 const udp_header *udp = (udp_header *)(packet + sizeof(ether_header)+sizeof(ip_header)); //udp header
                       		 u_char* udp_data = (u_char *)(packet + sizeof(ether_header) + sizeof(ip_header)+sizeof(udp_header));
                       		 uint32_t udp_size = (ntohs(ip->ip_len) - ip->ip_hl - sizeof(udp_header));
                       		 printf("UDP src port: %d\n", ntohs(udp->src));
                       		 printf("UDP dst port: %d\n", ntohs(udp->dst));

                       		 for (int i = 0; i < udp_size; i++)
                       		 {
                               		 printf("%02x ", udp_data[i]);
                       		 }
			 }

		}
					
		
	}

	pcap_close(handle);
	return 0;
}