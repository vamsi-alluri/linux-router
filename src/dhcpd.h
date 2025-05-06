#ifndef DHCPD_H
#define DHCPD_H

#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>

void dhcp_main(int rx_fd, int tx_fd);

/* DHCP Magic Cookie */
#define DHCP_MAGIC_COOKIE 0x63825363

/* DHCP Message Types */
#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

/* DHCP Options */
#define DHCP_OPTION_PAD              0
#define DHCP_OPTION_SUBNET_MASK      1
#define DHCP_OPTION_ROUTER           3
#define DHCP_OPTION_DNS_SERVER       6
#define DHCP_OPTION_DOMAIN_NAME      15
#define DHCP_OPTION_REQUESTED_IP     50
#define DHCP_OPTION_LEASE_TIME       51
#define DHCP_OPTION_MESSAGE_TYPE     53
#define DHCP_OPTION_SERVER_ID        54
#define DHCP_OPTION_PARAMETER_REQUEST 55
#define DHCP_OPTION_END              255

/* DHCP Packet Structure */
typedef struct
{
    uint8_t op;           /* Message op code / message type (1 = BOOTREQUEST, 2 = BOOTREPLY) */
    uint8_t htype;        /* Hardware address type (Ethernet = 1) */
    uint8_t hlen;         /* Hardware address length (Ethernet = 6) */
    uint8_t hops;         /* Clients set to 0, relays increment */
    uint32_t xid;         /* Transaction ID */
    uint16_t secs;        /* Seconds elapsed since client began acquisition */
    uint16_t flags;       /* Flags */
    uint32_t ciaddr;      /* Client IP address */
    uint32_t yiaddr;      /* 'Your' (client) IP address */
    uint32_t siaddr;      /* Next server IP address */
    uint32_t giaddr;      /* Relay agent IP address */
    uint8_t chaddr[16];   /* Client hardware address */
    uint8_t sname[64];    /* Server host name */
    uint8_t file[128];    /* Boot file name */
    uint8_t options[312]; /* Optional parameters field (variable) */
} dhcp_packet;

/* DHCP Lease Structure */
typedef struct
{
    uint32_t ip;        /* IP address */
    uint8_t mac[6];     /* MAC address */
    time_t lease_start; /* Lease start time */
    time_t lease_end;   /* Lease end time */
    int active;         /* Whether lease is active */
    time_t conflict_detected_time; /* Time when a conflict was last detected */
} dhcp_lease;

#endif /* DHCPD_H */
