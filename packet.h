#pragma once
#include <stdio.h>
#include <stdint.h>
#include "protocol/all.h"

void printTCPPort(uint16_t port);

void printIPAddress(ip_addr ipAddr);

void printMACAddress(mac_addr mac);