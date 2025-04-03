/* for the testing server */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <time.h>
#include "dhcp.h"

/* DHCP Constants */
#define DHCP_CLIENT_PORT 53630
#define DHCP_SERVER_PORT 53629

#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

#define DHCP_OPTION_MESSAGE_TYPE 53
#define DHCP_OPTION_REQUESTED_IP 50
#define DHCP_OPTION_SERVER_ID    54
#define DHCP_OPTION_END         255

#define DHCP_MAGIC_COOKIE 0x63825363


/* Helper function to print an IP address from a uint32_t in network byte order */
void print_ip(const char *msg, uint32_t ip)
{
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    printf("%s %s\n", msg, inet_ntoa(ip_addr));
}

/* Add a DHCP option to the options field */
int add_dhcp_option(uint8_t *options, int offset, uint8_t code, uint8_t len, const uint8_t *data)
{
    options[offset++] = code;  /* Option code */
    options[offset++] = len;   /* Length */
    memcpy(options + offset, data, len);
    offset += len;
    return offset;
}

/* Extract a specific DHCP option from the options array */
const uint8_t *get_dhcp_option(const uint8_t *options, size_t length, uint8_t option_code, size_t *opt_len)
{
    size_t i = 0;
    while (i < length) {
        uint8_t code = options[i];
        if (code == DHCP_OPTION_END) {
            break; /* end of options */
        } else if (code == option_code) {
            *opt_len = options[i + 1];
            return &options[i + 2];
        } else if (code == 0) {
            /* Pad option, just skip */
            i++;
        } else {
            i += 2 + options[i + 1]; /* skip this option */
        }
    }
    return NULL;
}

/* Prepare a generic DHCP packet with minimal fields set */
void prepare_dhcp_packet(dhcp_packet *packet, uint8_t msg_type, uint32_t xid, const uint8_t *client_mac)
{
    memset(packet, 0, sizeof(dhcp_packet));
    packet->op    = 1;  /* BOOTREQUEST */
    packet->htype = 1;  /* Ethernet */
    packet->hlen  = 6;  /* MAC length */
    packet->xid   = xid;
    packet->flags = htons(0x8000); /* Broadcast bit set */
    if (client_mac) {
        memcpy(packet->chaddr, client_mac, 6);
    }

    /* Magic cookie */
    uint32_t cookie = htonl(DHCP_MAGIC_COOKIE);
    memcpy(packet->options, &cookie, sizeof(cookie));

    /* DHCP Message Type */
    int offset = 4; /* After magic cookie */
    offset = add_dhcp_option(packet->options, offset, DHCP_OPTION_MESSAGE_TYPE, 1, &msg_type);

    /* End option (will append more if needed) */
    packet->options[offset] = DHCP_OPTION_END;
}

/* Send a DHCPDISCOVER and receive DHCPOFFER */
int send_dhcp_discover(int sock, struct sockaddr_in *server_addr, dhcp_packet *offer_packet, 
                       uint32_t xid, const uint8_t *client_mac)
{
    /* Build DHCPDISCOVER */
    dhcp_packet discover;
    prepare_dhcp_packet(&discover, DHCPDISCOVER, xid, client_mac);

    /* We can add additional options if desired (e.g., parameter request list). */

    /* Send the packet as broadcast */
    server_addr->sin_addr.s_addr = INADDR_BROADCAST; 
    if (sendto(sock, &discover, sizeof(discover), 0,
               (struct sockaddr*)server_addr, sizeof(*server_addr)) < 0) {
        perror("sendto() DHCPDISCOVER");
        return -1;
    }

    printf("DHCPDISCOVER sent. Waiting for DHCPOFFER...\n");

    /* Receive DHCPOFFER */
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t n = recvfrom(sock, offer_packet, sizeof(*offer_packet), 0,
                         (struct sockaddr*)&from_addr, &from_len);
    if (n < 0) {
        perror("recvfrom() DHCPOFFER");
        return -1;
    }

    /* Basic validation: check if it's a BOOTREPLY with the correct XID and magic cookie */
    if (offer_packet->op != 2 /* BOOTREPLY */) {
        printf("Not a BOOTREPLY, ignoring.\n");
        return -1;
    }
    if (offer_packet->xid != xid) {
        printf("XID mismatch, ignoring.\n");
        return -1;
    }
    uint32_t cookie;
    memcpy(&cookie, offer_packet->options, sizeof(cookie));
    if (ntohl(cookie) != DHCP_MAGIC_COOKIE) {
        printf("Invalid magic cookie in DHCPOFFER.\n");
        return -1;
    }

    printf("DHCPOFFER received.\n");
    return 0;
}

/* Send DHCPREQUEST and wait for DHCPACK (or DHCPNAK) */
int send_dhcp_request(int sock, struct sockaddr_in *server_addr, dhcp_packet *offer_packet,
                      uint32_t xid, const uint8_t *client_mac)
{
    /* Extract the offered IP and server ID from the DHCPOFFER */
    uint32_t offered_ip = offer_packet->yiaddr;

    size_t opt_len;
    const uint8_t *server_id_opt = get_dhcp_option(offer_packet->options + 4,
                                                   sizeof(offer_packet->options) - 4,
                                                   54 /* DHCP_OPTION_SERVER_ID */, &opt_len);

    uint32_t server_id = 0;
    if (server_id_opt && opt_len == 4) {
        memcpy(&server_id, server_id_opt, 4);
    }

    /* Prepare DHCPREQUEST */
    dhcp_packet request;
    memset(&request, 0, sizeof(request));
    request.op    = 1;  /* BOOTREQUEST */
    request.htype = 1;  /* Ethernet */
    request.hlen  = 6;
    request.xid   = xid;
    request.flags = htons(0x8000); /* broadcast */
    if (client_mac) {
        memcpy(request.chaddr, client_mac, 6);
    }

    /* Magic cookie */
    uint32_t cookie = htonl(DHCP_MAGIC_COOKIE);
    memcpy(request.options, &cookie, sizeof(cookie));

    int offset = 4;
    /* DHCP Message Type = DHCPREQUEST */
    uint8_t msg_type = DHCPREQUEST;
    offset = add_dhcp_option(request.options, offset, DHCP_OPTION_MESSAGE_TYPE, 1, &msg_type);

    /* Requested IP Address */
    offset = add_dhcp_option(request.options, offset, DHCP_OPTION_REQUESTED_IP, 4, (uint8_t*)&offered_ip);

    /* Server Identifier */
    offset = add_dhcp_option(request.options, offset, DHCP_OPTION_SERVER_ID, 4, (uint8_t*)&server_id);

    /* End */
    request.options[offset] = DHCP_OPTION_END;

    /* Send the packet (broadcast again) */
    server_addr->sin_addr.s_addr = INADDR_BROADCAST;
    if (sendto(sock, &request, sizeof(request), 0,
               (struct sockaddr*)server_addr, sizeof(*server_addr)) < 0) {
        perror("sendto() DHCPREQUEST");
        return -1;
    }
    printf("DHCPREQUEST sent. Waiting for DHCPACK/DHCPNAK...\n");

    /* Receive DHCPACK or DHCPNAK */
    dhcp_packet ack_packet;
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t n = recvfrom(sock, &ack_packet, sizeof(ack_packet), 0,
                         (struct sockaddr*)&from_addr, &from_len);
    if (n < 0) {
        perror("recvfrom() DHCPACK");
        return -1;
    }

    /* Validate */
    if (ack_packet.op != 2 /* BOOTREPLY */) {
        printf("Not a BOOTREPLY, ignoring.\n");
        return -1;
    }
    if (ack_packet.xid != xid) {
        printf("XID mismatch in DHCPACK.\n");
        return -1;
    }
    uint32_t ack_cookie;
    memcpy(&ack_cookie, ack_packet.options, sizeof(ack_cookie));
    if (ntohl(ack_cookie) != DHCP_MAGIC_COOKIE) {
        printf("Invalid magic cookie in DHCPACK.\n");
        return -1;
    }

    /* Check message type: ACK or NAK */
    size_t msg_opt_len;
    const uint8_t *msg_type_opt = get_dhcp_option(ack_packet.options + 4,
                                                  sizeof(ack_packet.options) - 4,
                                                  DHCP_OPTION_MESSAGE_TYPE,
                                                  &msg_opt_len);
    if (!msg_type_opt || msg_opt_len != 1) {
        printf("Invalid or missing DHCP message type in ACK.\n");
        return -1;
    }

    uint8_t ack_msg_type = *msg_type_opt;
    if (ack_msg_type == DHCPACK) {
        printf("DHCPACK received!\n");
        print_ip("Leased IP:", ack_packet.yiaddr);
    } else if (ack_msg_type == DHCPNAK) {
        printf("DHCPNAK received. Lease not granted.\n");
    } else {
        printf("Unexpected DHCP message type: %d\n", ack_msg_type);
    }

    return 0;
}

int main()
{
    int sock;
    struct sockaddr_in client_addr, server_addr;
    dhcp_packet offer_packet;

    /* Create a UDP socket */
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("socket()");
        return 1;
    }

    /* Allow socket to do broadcasts */
    int broadcast = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
        perror("setsockopt() SO_BROADCAST");
        close(sock);
        return 1;
    }

    /* Bind to client port 68 */
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family      = AF_INET;
    client_addr.sin_port        = htons(DHCP_CLIENT_PORT);
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("bind()");
        close(sock);
        return 1;
    }

    /* Prepare the server_addr for sending broadcast to port 67 */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(DHCP_SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_BROADCAST; /* We'll set it again before sending */

    printf("DHCP Client starting...\n");

    /* Generate a random XID (transaction ID) */
    srand(time(NULL));
    uint32_t xid = rand();

    /* (Optional) You can retrieve your MAC address from an interface.
       For testing, we’ll just use a dummy MAC: 00:11:22:33:44:55 */
    uint8_t client_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    /* 1. Send DHCPDISCOVER and receive DHCPOFFER */
    if (send_dhcp_discover(sock, &server_addr, &offer_packet, xid, client_mac) < 0) {
        printf("Failed to receive DHCPOFFER.\n");
        close(sock);
        return 1;
    }

    /* 2. Send DHCPREQUEST and wait for DHCPACK/DHCPNAK */
    if (send_dhcp_request(sock, &server_addr, &offer_packet, xid, client_mac) < 0) {
        printf("Failed to receive DHCPACK or DHCPNAK.\n");
        close(sock);
        return 1;
    }

    printf("DHCP client done.\n");
    close(sock);
    return 0;
}