#pragma once
#include <stdio.h>
#include <stdint.h>
#include "protocol/all.h"

void printTCPPort(uint16_t port);

void printIPAddress(ip_addr ipAddr);

void printMACAddress(mac_addr mac);

void printICMPDATA(u_char* data, uint32_t size);

void printPacket(const unsigned char *p, uint32_t size);