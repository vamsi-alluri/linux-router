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
#define DHCP_CLIENT_PORT 53630
#define DHCP_SERVER_PORT 53629
#define MAX_THREADS 20

/* DHCP Message Types */
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNAK 6
#define DHCPRELEASE 7
#define DHCPINFORM 8

/* DHCP Options */
#define DHCP_OPTION_PAD 0
#define DHCP_OPTION_SUBNET_MASK 1
#define DHCP_OPTION_ROUTER 3
#define DHCP_OPTION_DNS_SERVER 6
#define DHCP_OPTION_DOMAIN_NAME 15
#define DHCP_OPTION_REQUESTED_IP 50
#define DHCP_OPTION_LEASE_TIME 51
#define DHCP_OPTION_MESSAGE_TYPE 53
#define DHCP_OPTION_SERVER_ID 54
#define DHCP_OPTION_PARAMETER_REQUEST 55
#define DHCP_OPTION_END 255

#define DHCP_MAGIC_COOKIE 0x63825363
#define MAX_LEASES 10
dhcp_lease leases[MAX_LEASES];
pthread_mutex_t lease_mutex = PTHREAD_MUTEX_INITIALIZER; 
pthread_mutex_t thread_count_mutex = PTHREAD_MUTEX_INITIALIZER; 
int thread_count = 0; 

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

/* lease table */
void init_leases()
{
    pthread_mutex_lock(&lease_mutex);
    for (int i = 0; i < MAX_LEASES; i++)
    {
        leases[i].active = 0;
    }
    pthread_mutex_unlock(&lease_mutex);
}

/* Add a DHCP option to the options field. */
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

    pthread_mutex_lock(&lease_mutex);
    // Check if this MAC already has a lease
    for (i = 0; i < MAX_LEASES; i++)
    {
        if (leases[i].active && memcmp(leases[i].mac, mac, 6) == 0)
        {
            leases[i].lease_start = now;
            leases[i].lease_end = now + lease_time;
            allocated_ip = leases[i].ip;
            break;
        }
    }
    // If no existing lease, allocate a new one
    if (allocated_ip == 0)
    {
        for (i = 0; i < MAX_LEASES; i++)
        {
            if (!leases[i].active || leases[i].lease_end < now)
            {
                leases[i].active = 1;
                memcpy(leases[i].mac, mac, 6);
                leases[i].lease_start = now;
                leases[i].lease_end = now + lease_time;
                leases[i].ip = htonl(0xC0A80A00 | (i + 100));
                allocated_ip = leases[i].ip;
                break;
            }
        }
    }
    pthread_mutex_unlock(&lease_mutex);
    return allocated_ip;
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
        // Build DHCP OFFER packet
        dhcp_packet offer;
        int offset = create_dhcp_packet(&offer, DHCPOFFER, packet.xid, 0, new_ip, packet.chaddr);
        uint32_t lease_time = htonl(3600);
        offset = add_dhcp_option(offer.options, offset, DHCP_OPTION_LEASE_TIME, 4, (uint8_t *)&lease_time);
        uint32_t server_id = si_other.sin_addr.s_addr;
        offset = add_dhcp_option(offer.options, offset, DHCP_OPTION_SERVER_ID, 4, (uint8_t *)&server_id);
        uint32_t subnet_mask = htonl(0xFFFFFF00); // 255.255.255.0
        offset = add_dhcp_option(offer.options, offset, DHCP_OPTION_SUBNET_MASK, 4, (uint8_t *)&subnet_mask);
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
        // Verify if the requested IP is valid
        int found = 0;
        for (int i = 0; i < MAX_LEASES; i++)
        {
            if (leases[i].active && leases[i].ip == req_ip &&
                memcmp(leases[i].mac, packet.chaddr, 6) == 0)
            {
                found = 1;
                leases[i].lease_start = time(NULL);
                leases[i].lease_end = leases[i].lease_start + 3600;
                break;
            }
        }
        // Build DHCP ACK or NAK packet
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
            uint32_t subnet_mask = htonl(0xFFFFFF00);
            offset = add_dhcp_option(ack.options, offset, DHCP_OPTION_SUBNET_MASK, 4, (uint8_t *)&subnet_mask);
            ack.options[offset++] = DHCP_OPTION_END;
        }
        else
        {
            int offset = create_dhcp_packet(&ack, DHCPNAK, packet.xid, 0, 0, packet.chaddr);
            printf("[Thread %lu] Sending DHCP NAK to client\n", pthread_self());
            ack.options[offset++] = DHCP_OPTION_END;
        }
        if (sendto(s, &ack, sizeof(ack), 0, (struct sockaddr *)&si_other, slen) == -1)
            perror("sendto()");
        break;
    }
    case DHCPRELEASE:
    {
        printf("[Thread %lu] DHCP RELEASE received from client\n", pthread_self());
        for (int i = 0; i < MAX_LEASES; i++)
        {
            if (leases[i].active && memcmp(leases[i].mac, packet.chaddr, 6) == 0)
            {
                leases[i].active = 0;
                printf("[Thread %lu] Released IP: %s\n",
                       pthread_self(), inet_ntoa(*(struct in_addr *)&leases[i].ip));
                break;
            }
        }
        break;
    }
    default:
        printf("[Thread %lu] Unsupported DHCP message type: %d\n", pthread_self(), msg_type);
    }

    free(thread_arg);
    

    pthread_mutex_lock(&thread_count_mutex);
    thread_count--;
    pthread_mutex_unlock(&thread_count_mutex);
    
    pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
    struct sockaddr_in si_me, si_other;
    struct timeval timeout = {0, 0};
    fd_set readfds;
    int s, slen = sizeof(si_other), recv_len, portno, select_ret;
    pthread_t thread_id;

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

            pthread_mutex_lock(&thread_count_mutex);
            if (thread_count >= MAX_THREADS)
            {
                pthread_mutex_unlock(&thread_count_mutex);
                printf("Maximum number of threads reached. Rejecting request.\n");
                free(thread_arg);
                continue;
            }
            thread_count++;
            pthread_mutex_unlock(&thread_count_mutex);

            if (pthread_create(&thread_id, NULL, handle_dhcp_request, thread_arg) != 0)
            {
                perror("pthread_create failed");
                pthread_mutex_lock(&thread_count_mutex);
                thread_count--;
                pthread_mutex_unlock(&thread_count_mutex);
                free(thread_arg);
                continue;
            }

            pthread_detach(thread_id);

            printf("Created thread %lu to handle request (active threads: %d)\n",
                   thread_id, thread_count);
        }
    }

    pthread_mutex_destroy(&lease_mutex);
    pthread_mutex_destroy(&thread_count_mutex);
    close(s);
    return 0;
}
