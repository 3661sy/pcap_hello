#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "protocol/all.h"


void printTCPPort(uint16_t port)
{
	printf("%d", port);
}

void printIPAddress(ip_addr ipAddr)
{
	printf("%d.%d.%d.%d\n", ipAddr.a, ipAddr.b, ipAddr.c, ipAddr.d);
}

void printMACAddress(mac_addr mac)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac.oui[0], mac.oui[1], mac.oui[2], mac.nic[0], mac.nic[1], mac.nic[2]);
}
