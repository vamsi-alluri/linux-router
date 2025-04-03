/*
    Compilation: gcc -o DHCPserver DHCPserver.c -lpthread
    Execution  : ./DHCPserver <port_number>
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include "dhcp.h"

#define BUFLEN 512 // Max length of buffer
#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67
#define MAX_THREADS 20

/* DHCP Message Types */
#define DHCPDISCOVER 1
#define DHCPOFFER   2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK     5
#define DHCPNAK     6
#define DHCPRELEASE 7
#define DHCPINFORM  8

/* DHCP Options */
#define DHCP_OPTION_PAD             0
#define DHCP_OPTION_SUBNET_MASK     1
#define DHCP_OPTION_ROUTER          3
#define DHCP_OPTION_DNS_SERVER      6
#define DHCP_OPTION_DOMAIN_NAME     15
#define DHCP_OPTION_REQUESTED_IP    50
#define DHCP_OPTION_LEASE_TIME      51
#define DHCP_OPTION_MESSAGE_TYPE    53
#define DHCP_OPTION_SERVER_ID       54
#define DHCP_OPTION_PARAMETER_REQUEST 55
#define DHCP_OPTION_END             255

/* DHCP Magic Cookie */
#define DHCP_MAGIC_COOKIE 0x63825363
#define MAX_LEASES 10
#define MAX_LEASES_PER_SUBNET 10

/* Define multiple subnets */
typedef struct {
    uint32_t network;     // Network address in host byte order
    uint32_t netmask;     // Netmask in host byte order
    uint32_t start_ip;    // First allocatable IP in host byte order
    uint32_t router_ip;   // Router IP for this subnet in host byte order
    uint32_t dns_ip;      // DNS server IP for this subnet in host byte order
} dhcp_subnet;

dhcp_subnet subnets[2] = {
    {0xC0A80A00, 0xFFFFFF00, 0xC0A80A64, 0xC0A80A01, 0xC0A80A01}, // 192.168.10.0/24, starting .100
    {0xC0A81400, 0xFFFFFF00, 0xC0A81464, 0xC0A81401, 0xC0A81401}  // 192.168.20.0/24, starting .100
};

typedef struct {
    int active;           // 1 if lease is active, 0 otherwise
    uint8_t mac[6];       // Client MAC address
    uint32_t ip;          // Assigned IP address in network byte order
    time_t lease_start;   // When the lease began
    time_t lease_end;     // When the lease expires
    int subnet_idx;       // Which subnet this lease belongs to
} dhcp_lease;

dhcp_lease leases[MAX_LEASES * 2]; // Double the size for two subnets
pthread_mutex_t lease_mutex = PTHREAD_MUTEX_INITIALIZER; // Mutex for lease table access

typedef struct
{
    struct sockaddr_in client_addr;
    dhcp_packet packet;
    int socket;
    int recv_len;
} thread_arg_t;

void die(char *s)
{
    perror(s);
    exit(1);
}

/* Initialize lease table */
void init_leases()
{
    pthread_mutex_lock(&lease_mutex);
    for (int i = 0; i < MAX_LEASES * 2; i++)
    {
        leases[i].active = 0;
    }
    pthread_mutex_unlock(&lease_mutex);
}

/* Add a DHCP option to the options field.
   Returns the new offset after appending the option. */
int add_dhcp_option(uint8_t *options, int offset, uint8_t code, uint8_t len, const uint8_t *data)
{
    options[offset++] = code;
    options[offset++] = len;
    memcpy(&options[offset], data, len);
    return offset + len;
}

/* Find DHCP option in options field.
   Returns pointer to option data and its length in *len if found, else NULL. */
const uint8_t *get_dhcp_option(const uint8_t *options, size_t options_len, uint8_t code, size_t *len)
{
    const uint8_t *end = options + options_len;
    const uint8_t *curr = options;

    while (curr < end && *curr != DHCP_OPTION_END)
    {
        if (*curr == DHCP_OPTION_PAD)
        {
            curr++;
            continue;
        }
        if (*curr == code)
        {
            *len = *(curr + 1);
            return curr + 2;
        }
        curr += 2 + *(curr + 1);
    }
    return NULL;
}

/* Create a DHCP packet with fixed fields and basic options.
   Returns the next free offset in the options field for further options. */
int create_dhcp_packet(dhcp_packet *packet, uint8_t msg_type, uint32_t xid,
    uint32_t ciaddr, uint32_t yiaddr, const uint8_t *chaddr)
{
    memset(packet, 0, sizeof(dhcp_packet));

    packet->op = 2;    // BOOTREPLY
    packet->htype = 1; // Ethernet
    packet->hlen = 6;  // MAC address length
    packet->hops = 0;
    packet->xid = xid;
    packet->secs = 0;
    packet->flags = 0;
    packet->ciaddr = ciaddr;
    packet->yiaddr = yiaddr;
    packet->siaddr = 0;
    packet->giaddr = 0;
    if (chaddr)
        memcpy(packet->chaddr, chaddr, 6);

    // Set DHCP magic cookie (first 4 bytes)
    uint32_t magic_cookie = htonl(DHCP_MAGIC_COOKIE);
    memcpy(packet->options, &magic_cookie, sizeof(magic_cookie));

    int offset = 4; // start after magic cookie

    // Add DHCP message type option
    offset = add_dhcp_option(packet->options, offset, DHCP_OPTION_MESSAGE_TYPE, 1, &msg_type);

    return offset;
}

/* Allocate an IP address based on the client's MAC address and lease time.
   Returns the allocated IP in network byte order. */
uint32_t allocate_ip(const uint8_t *mac, time_t lease_time)
{
    int i;
    time_t now = time(NULL);
    uint32_t allocated_ip = 0;
    int subnet_idx = 0; // Default to first subnet

    pthread_mutex_lock(&lease_mutex);
    
    // Check if this MAC already has a lease in any subnet
    for (i = 0; i < MAX_LEASES * 2; i++)
    {
        if (leases[i].active && memcmp(leases[i].mac, mac, 6) == 0)
        {
            leases[i].lease_start = now;
            leases[i].lease_end = now + lease_time;
            allocated_ip = leases[i].ip;
            subnet_idx = leases[i].subnet_idx;
            break;
        }
    }
    
    // If no existing lease, allocate a new one
    // Try first subnet, then second if first is full
    if (allocated_ip == 0)
    {
        for (subnet_idx = 0; subnet_idx < 2; subnet_idx++) {
            int start_idx = subnet_idx * MAX_LEASES;
            int end_idx = start_idx + MAX_LEASES;
            
            for (i = start_idx; i < end_idx; i++)
            {
                if (!leases[i].active || leases[i].lease_end < now)
                {
                    leases[i].active = 1;
                    memcpy(leases[i].mac, mac, 6);
                    leases[i].lease_start = now;
                    leases[i].lease_end = now + lease_time;
                    leases[i].subnet_idx = subnet_idx;
                    
                    // Calculate IP based on subnet and index
                    uint32_t ip_host = subnets[subnet_idx].start_ip + (i - start_idx);
                    leases[i].ip = htonl(ip_host);
                    allocated_ip = leases[i].ip;
                    break;
                }
            }
            
            if (allocated_ip != 0) {
                break; // Found an IP, no need to check second subnet
            }
        }
    }
    
    pthread_mutex_unlock(&lease_mutex);
    return allocated_ip;
}

/* Find a lease by IP address */
int find_lease_by_ip(uint32_t ip) 
{
    for (int i = 0; i < MAX_LEASES * 2; i++) {
        if (leases[i].active && leases[i].ip == ip) {
            return i;
        }
    }
    return -1;
}

/* Get subnet index for a given IP */
int get_subnet_idx(uint32_t ip) 
{
    uint32_t ip_host = ntohl(ip);
    for (int i = 0; i < 2; i++) {
        if ((ip_host & subnets[i].netmask) == subnets[i].network) {
            return i;
        }
    }
    return -1; // Not in our subnets
}

/* Thread function to handle DHCP client requests */
void *handle_dhcp_request(void *arg)
{
    thread_arg_t *thread_arg = (thread_arg_t *)arg;
    struct sockaddr_in si_other = thread_arg->client_addr;
    dhcp_packet packet = thread_arg->packet;
    int s = thread_arg->socket;
    int slen = sizeof(si_other);

    printf("[Thread %lu] Handling request from %s, port number:%d\n",
           pthread_self(), inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));

    // Verify magic cookie
    uint32_t magic_cookie;
    memcpy(&magic_cookie, packet.options, sizeof(magic_cookie));
    magic_cookie = ntohl(magic_cookie);
    if (magic_cookie != DHCP_MAGIC_COOKIE)
    {
        printf("[Thread %lu] Invalid DHCP packet (wrong magic cookie)\n", pthread_self());
        free(thread_arg);
        pthread_exit(NULL);
    }

    // Extract DHCP message type option
    size_t opt_len;
    const uint8_t *msg_type_opt = get_dhcp_option(packet.options + 4, sizeof(packet.options) - 4,
                                                  DHCP_OPTION_MESSAGE_TYPE, &opt_len);
    if (!msg_type_opt || opt_len != 1)
    {
        printf("[Thread %lu] Invalid DHCP packet (no message type)\n", pthread_self());
        free(thread_arg);
        pthread_exit(NULL);
    }
    uint8_t msg_type = *msg_type_opt;

    switch (msg_type)
    {
    case DHCPDISCOVER:
    {
        printf("[Thread %lu] DHCP DISCOVER received from client\n", pthread_self());
        uint32_t new_ip = allocate_ip(packet.chaddr, 3600);
        if (!new_ip)
        {
            printf("[Thread %lu] No more IP addresses available\n", pthread_self());
            free(thread_arg);
            pthread_exit(NULL);
        }
        
        // Get subnet info for the allocated IP
        int subnet_idx = get_subnet_idx(new_ip);
        if (subnet_idx == -1) {
            printf("[Thread %lu] Error: IP not in known subnet\n", pthread_self());
            free(thread_arg);
            pthread_exit(NULL);
        }
        
        // Build DHCP OFFER packet
        dhcp_packet offer;
        int offset = create_dhcp_packet(&offer, DHCPOFFER, packet.xid, 0, new_ip, packet.chaddr);
        uint32_t lease_time = htonl(3600);
        offset = add_dhcp_option(offer.options, offset, DHCP_OPTION_LEASE_TIME, 4, (uint8_t *)&lease_time);
        uint32_t server_id = si_other.sin_addr.s_addr;
        offset = add_dhcp_option(offer.options, offset, DHCP_OPTION_SERVER_ID, 4, (uint8_t *)&server_id);
        
        // Add subnet mask
        uint32_t subnet_mask = htonl(subnets[subnet_idx].netmask);
        offset = add_dhcp_option(offer.options, offset, DHCP_OPTION_SUBNET_MASK, 4, (uint8_t *)&subnet_mask);
        
        // Add router (gateway)
        uint32_t router_ip = htonl(subnets[subnet_idx].router_ip);
        offset = add_dhcp_option(offer.options, offset, DHCP_OPTION_ROUTER, 4, (uint8_t *)&router_ip);
        
        // Add DNS server
        uint32_t dns_ip = htonl(subnets[subnet_idx].dns_ip);
        offset = add_dhcp_option(offer.options, offset, DHCP_OPTION_DNS_SERVER, 4, (uint8_t *)&dns_ip);
        
        // Terminate options
        offer.options[offset++] = DHCP_OPTION_END;

        printf("[Thread %lu] Sending DHCP OFFER to client with IP: %s\n",
               pthread_self(), inet_ntoa(*(struct in_addr *)&new_ip));
        if (sendto(s, &offer, sizeof(offer), 0, (struct sockaddr *)&si_other, slen) == -1)
            perror("sendto()");
        break;
    }
    case DHCPREQUEST:
    {
        printf("[Thread %lu] DHCP REQUEST received from client\n", pthread_self());
        size_t opt_len;
        const uint8_t *req_ip_opt = get_dhcp_option(packet.options + 4, sizeof(packet.options) - 4,
                                                    DHCP_OPTION_REQUESTED_IP, &opt_len);
        uint32_t req_ip = 0;
        if (req_ip_opt && opt_len == 4)
        {
            memcpy(&req_ip, req_ip_opt, 4);
        }
        else
        {
            req_ip = packet.ciaddr;
        }
        
        // Get subnet index for requested IP
        int subnet_idx = get_subnet_idx(req_ip);
        if (subnet_idx == -1) {
            printf("[Thread %lu] Requested IP not in our subnets\n", pthread_self());
            subnet_idx = 0; // Default to first subnet for NAK
        }
        
        // Verify if the requested IP is valid
        int lease_idx = find_lease_by_ip(req_ip);
        int found = 0;
        
        if (lease_idx != -1 && memcmp(leases[lease_idx].mac, packet.chaddr, 6) == 0) {
            found = 1;
            pthread_mutex_lock(&lease_mutex);
            leases[lease_idx].lease_start = time(NULL);
            leases[lease_idx].lease_end = leases[lease_idx].lease_start + 3600;
            pthread_mutex_unlock(&lease_mutex);
            subnet_idx = leases[lease_idx].subnet_idx;
        }
        
        // Build DHCP ACK or NAK packet accordingly
        dhcp_packet ack;
        if (found)
        {
            int offset = create_dhcp_packet(&ack, DHCPACK, packet.xid, 0, req_ip, packet.chaddr);
            printf("[Thread %lu] Sending DHCP ACK to client for IP: %s\n",
                   pthread_self(), inet_ntoa(*(struct in_addr *)&req_ip));
            uint32_t lease_time = htonl(3600);
            offset = add_dhcp_option(ack.options, offset, DHCP_OPTION_LEASE_TIME, 4, (uint8_t *)&lease_time);
            uint32_t server_id = si_other.sin_addr.s_addr;
            offset = add_dhcp_option(ack.options, offset, DHCP_OPTION_SERVER_ID, 4, (uint8_t *)&server_id);
            
            // Add subnet mask
            uint32_t subnet_mask = htonl(subnets[subnet_idx].netmask);
            offset = add_dhcp_option(ack.options, offset, DHCP_OPTION_SUBNET_MASK, 4, (uint8_t *)&subnet_mask);
            
            // Add router (gateway)
            uint32_t router_ip = htonl(subnets[subnet_idx].router_ip);
            offset = add_dhcp_option(ack.options, offset, DHCP_OPTION_ROUTER, 4, (uint8_t *)&router_ip);
            
            // Add DNS server
            uint32_t dns_ip = htonl(subnets[subnet_idx].dns_ip);
            offset = add_dhcp_option(ack.options, offset, DHCP_OPTION_DNS_SERVER, 4, (uint8_t *)&dns_ip);
            
            ack.options[offset++] = DHCP_OPTION_END;
        }
        else
        {
            int offset = create_dhcp_packet(&ack, DHCPNAK, packet.xid, 0, 0, packet.chaddr);
            printf("[Thread %lu] Sending DHCP NAK to client\n", pthread_self());
            
            // Add server identifier option even for NAK
            uint32_t server_id = si_other.sin_addr.s_addr;
            offset = add_dhcp_option(ack.options, offset, DHCP_OPTION_SERVER_ID, 4, (uint8_t *)&server_id);
            
            ack.options[offset++] = DHCP_OPTION_END;
        }
        if (sendto(s, &ack, sizeof(ack), 0, (struct sockaddr *)&si_other, slen) == -1)
            perror("sendto()");
        break;
    }
    case DHCPRELEASE:
    {
        printf("[Thread %lu] DHCP RELEASE received from client\n", pthread_self());
        pthread_mutex_lock(&lease_mutex);
        for (int i = 0; i < MAX_LEASES * 2; i++) // Search through all subnets
        {
            if (leases[i].active && memcmp(leases[i].mac, packet.chaddr, 6) == 0)
            {
                leases[i].active = 0;
                printf("[Thread %lu] Released IP: %s\n",
                       pthread_self(), inet_ntoa(*(struct in_addr *)&leases[i].ip));
                break;
            }
        }
        pthread_mutex_unlock(&lease_mutex);
        break;
    }
    default:
        printf("[Thread %lu] Unsupported DHCP message type: %d\n", pthread_self(), msg_type);
    }

    free(thread_arg);
    pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
    struct sockaddr_in si_me, si_other;
    struct timeval timeout = {0, 0};
    fd_set readfds;
    int s, slen = sizeof(si_other), recv_len, portno, select_ret;
    pthread_t thread_id;
    int thread_count = 0;

    init_leases();

    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        die("socket");

    memset((char *)&si_me, 0, sizeof(si_me));
    portno = atoi(argv[1]);
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(portno);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *)&si_me, sizeof(si_me)) == -1)
        die("bind");

    system("clear");
    printf("...This is DHCP server (Concurrent Version)...\n\n");

    while (1)
    {
        FD_ZERO(&readfds);
        FD_SET(s, &readfds);
        select_ret = select(s + 1, &readfds, NULL, NULL, &timeout);

        if (select_ret > 0)
        {
            dhcp_packet packet;
            memset(&packet, 0, sizeof(packet));
            if ((recv_len = recvfrom(s, &packet, sizeof(packet), 0,
                                      (struct sockaddr *)&si_other, &slen)) == -1)
                die("recvfrom()");

            printf("Received packet from %s, port number:%d\n",
                   inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));

            if (thread_count >= MAX_THREADS)
            {
                printf("Maximum number of threads reached. Rejecting request.\n");
                continue;
            }

            thread_arg_t *thread_arg = malloc(sizeof(thread_arg_t));
            if (!thread_arg)
            {
                perror("malloc failed");
                continue;
            }
            thread_arg->client_addr = si_other;
            thread_arg->packet = packet;
            thread_arg->socket = s;
            thread_arg->recv_len = recv_len;

            if (pthread_create(&thread_id, NULL, handle_dhcp_request, thread_arg) != 0)
            {
                perror("pthread_create failed");
                free(thread_arg);
                continue;
            }

            pthread_detach(thread_id);
            thread_count++;

            printf("Created thread %lu to handle request (active threads: %d)\n",
                   thread_id, thread_count);
        }
    }

    pthread_mutex_destroy(&lease_mutex);
    close(s);
    return 0;
}
