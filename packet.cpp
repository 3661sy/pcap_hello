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

void printICMPDATA(u_char *data, uint32_t size)
{
	printf("ICMP size: %d\n", size);
	printf("ICMP Identifier: ");
	for (int i = 0; i < 2; i++)
	{
		printf("%02x ", data[i]);
	}
	printf("\n");
	printf("ICMP Seq num: ");
	for (int i = 2; i < 4; i++)
	{
		printf("%02x ", data[i]);
	}
	printf("\n");
	printf("Timestamp: ");
	for (int i = 4; i < 12; i++)
	{
		printf("%02x ", data[i]);
	}
	printf("\n");
	printf("ICMP Data: ");
	for (int i = 12; i < size; i++)
	{
		if (i % 8 == 0)
		{
			printf("\n");
			if (i % 16 == 0)
			{
				printf("\n");
			}
		}
		printf("%02x ", data[i]);
	}

	printf("\n");
}

void printPacket(const unsigned char *p, uint32_t size)
{

	int len = 0;
	while (len < size)
	{
		if (!(len % 16))
		{
			printf("%04x ", len);
		}

		printf("%02x ", *(p + len));

		if (!((len + 1) % 8))
		{
			printf("	");
		}

		len++;

		if (!((len) % 16) || (size - len) == 0)
		{
			int length = (size - len) == 0 ? size % 16 : 16;
			if (length < 16)
			{
				for (int i = 0; i < 16 - length; i++)
				{
					printf("    ");
					if (!((i + 1) % 8))
					{
						printf("   ");
					}
				}
				printf("    ");
			}

			for (int i = 0; i < length; i++)
			{
				uint8_t nowChar = *(p + (len - (length - i)));
				if (nowChar >= 33 && nowChar <= 126)
				{
					printf("%c ", nowChar);
				}
				else
				{
					printf(". ");
				}

				if (!((i + 1) % 8))
				{
					printf("	");
				}
			}

			printf("\n");
		}
	}
}