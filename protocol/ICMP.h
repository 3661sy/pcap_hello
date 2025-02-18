#pragma once
#include <stdint.h>

#define ICMP_ECHOREPLY  0        /* Echo Reply                        */
#define ICMP_DEST_UNREACH        3        /* Destination Unreachable        */
#define ICMP_SOURCE_QUENCH  4        /* Source Quench                */
#define ICMP_REDIRECT   5        /* Redirect (change route)        */
#define ICMP_ECHO   8        /* Echo Request                        */
#define ICMP_TIME_EXCEEDED  11        /* Time Exceeded                */
#define ICMP_PARAMETERPROB  12        /* Parameter Problem                */
#define ICMP_TIMESTAMP  13        /* Timestamp Request                */
#define ICMP_TIMESTAMPREPLY 14        /* Timestamp Reply                */
#define ICMP_INFO_REQUEST   15        /* Information Request                */
#define ICMP_INFO_REPLY 16        /* Information Reply                */
#define ICMP_ADDRESS    17        /* Address Mask Request                */
#define ICMP_ADDRESSREPLY   18        /* Address Mask Reply                */
#define NR_ICMP_TYPES   18

struct __attribute__((aligned(1), packed_)) ICMP_HEADER
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
};
