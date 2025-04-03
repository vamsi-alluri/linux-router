/*
    DHCP Client for testing multi-subnet DHCP server
    Compilation: gcc -o dhcp_client dhcp_client.c
    Execution: ./dhcp_client [-c count] [-r] [-i interface] [-m mac_addr]
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>
#include <pthread.h>
#include <getopt.h>
#include "dhcp.h"

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67
#define MAX_CLIENTS 20
#define DEFAULT_INTERFACE "eth0"

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

typedef struct {
    int active;
    uint8_t mac[6];
    uint32_t xid;
    uint32_t server_id;
    uint32_t offered_ip;
    uint32_t assigned_ip;
    uint32_t subnet_mask;
    uint32_t router_ip;
    uint32_t dns_ip;
    uint32_t lease_time;
    pthread_t thread_id;
} client_state;

client_state clients[MAX_CLIENTS];
pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Globals */
int g_release_after = 0;
char g_interface[IFNAMSIZ] = DEFAULT_INTERFACE;

void die(char *s)
{
    perror(s);
    exit(1);
}

/* Add a DHCP option to the options field */
int add_dhcp_option(uint8_t *options, int offset, uint8_t code, uint8_t len, const uint8_t *data)
{
    options[offset++] = code;
    options[offset++] = len;
    memcpy(&options[offset], data, len);
    return offset + len;
}

/* Get a DHCP option from options field */
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

/* Create a DHCP DISCOVER packet */
void create_dhcp_discover(dhcp_packet *packet, const uint8_t *mac, uint32_t xid)
{
    memset(packet, 0, sizeof(dhcp_packet));
    
    packet->op = 1; // BOOTREQUEST
    packet->htype = 1; // Ethernet
    packet->hlen = 6; // MAC address length
    packet->hops = 0;
    packet->xid = xid;
    packet->secs = htons(0);
    packet->flags = htons(0x8000); // Broadcast flag
    memcpy(packet->chaddr, mac, 6);
    
    // Set DHCP magic cookie
    uint32_t magic_cookie = htonl(DHCP_MAGIC_COOKIE);
    memcpy(packet->options, &magic_cookie, sizeof(magic_cookie));
    
    int offset = 4; // Start after magic cookie
    
    // Add DHCP message type option
    uint8_t msg_type = DHCPDISCOVER;
    offset = add_dhcp_option(packet->options, offset, DHCP_OPTION_MESSAGE_TYPE, 1, &msg_type);
    
    // Add parameter request list
    uint8_t params[] = {
        DHCP_OPTION_SUBNET_MASK,
        DHCP_OPTION_ROUTER,
        DHCP_OPTION_DNS_SERVER
    };
    offset = add_dhcp_option(packet->options, offset, DHCP_OPTION_PARAMETER_REQUEST, 
                           sizeof(params), params);
    
    // End options
    packet->options[offset++] = DHCP_OPTION_END;
}

/* Create a DHCP REQUEST packet */
void create_dhcp_request(dhcp_packet *packet, const uint8_t *mac, uint32_t xid, 
                         uint32_t requested_ip, uint32_t server_id)
{
    memset(packet, 0, sizeof(dhcp_packet));
    
    packet->op = 1; // BOOTREQUEST
    packet->htype = 1; // Ethernet
    packet->hlen = 6; // MAC address length
    packet->hops = 0;
    packet->xid = xid;
    packet->secs = htons(0);
    packet->flags = htons(0x8000); // Broadcast flag
    memcpy(packet->chaddr, mac, 6);
    
    // Set DHCP magic cookie
    uint32_t magic_cookie = htonl(DHCP_MAGIC_COOKIE);
    memcpy(packet->options, &magic_cookie, sizeof(magic_cookie));
    
    int offset = 4; // Start after magic cookie
    
    // Add DHCP message type option
    uint8_t msg_type = DHCPREQUEST;
    offset = add_dhcp_option(packet->options, offset, DHCP_OPTION_MESSAGE_TYPE, 1, &msg_type);
    
    // Add requested IP address
    offset = add_dhcp_option(packet->options, offset, DHCP_OPTION_REQUESTED_IP, 4, 
                           (uint8_t *)&requested_ip);
    
    // Add server identifier
    offset = add_dhcp_option(packet->options, offset, DHCP_OPTION_SERVER_ID, 4, 
                           (uint8_t *)&server_id);
    
    // Add parameter request list
    uint8_t params[] = {
        DHCP_OPTION_SUBNET_MASK,
        DHCP_OPTION_ROUTER,
        DHCP_OPTION_DNS_SERVER
    };
    offset = add_dhcp_option(packet->options, offset, DHCP_OPTION_PARAMETER_REQUEST, 
                           sizeof(params), params);
    
    // End options
    packet->options[offset++] = DHCP_OPTION_END;
}

/* Create a DHCP RELEASE packet */
void create_dhcp_release(dhcp_packet *packet, const uint8_t *mac, uint32_t xid, 
                         uint32_t client_ip, uint32_t server_id)
{
    memset(packet, 0, sizeof(dhcp_packet));
    
    packet->op = 1; // BOOTREQUEST
    packet->htype = 1; // Ethernet
    packet->hlen = 6; // MAC address length
    packet->hops = 0;
    packet->xid = xid;
    packet->secs = htons(0);
    packet->ciaddr = client_ip; // Fill in client IP
    memcpy(packet->chaddr, mac, 6);
    
    // Set DHCP magic cookie
    uint32_t magic_cookie = htonl(DHCP_MAGIC_COOKIE);
    memcpy(packet->options, &magic_cookie, sizeof(magic_cookie));
    
    int offset = 4; // Start after magic cookie
    
    // Add DHCP message type option
    uint8_t msg_type = DHCPRELEASE;
    offset = add_dhcp_option(packet->options, offset, DHCP_OPTION_MESSAGE_TYPE, 1, &msg_type);
    
    // Add server identifier
    offset = add_dhcp_option(packet->options, offset, DHCP_OPTION_SERVER_ID, 4, 
                           (uint8_t *)&server_id);
    
    // End options
    packet->options[offset++] = DHCP_OPTION_END;
}

/* Generate a random MAC address */
void generate_random_mac(uint8_t *mac)
{
    srand(time(NULL) ^ (intptr_t)mac);
    for (int i = 0; i < 6; i++) {
        mac[i] = rand() % 256;
    }
    // Make it a locally administered MAC
    mac[0] &= 0xFE; // Clear multicast bit
    mac[0] |= 0x02; // Set locally administered bit
}

/* Print MAC address */
void print_mac(const uint8_t *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Check if packet contains a specific DHCP message type */
int is_dhcp_message(const dhcp_packet *packet, uint8_t message_type)
{
    // Check magic cookie
    uint32_t magic_cookie;
    memcpy(&magic_cookie, packet->options, sizeof(magic_cookie));
    magic_cookie = ntohl(magic_cookie);
    if (magic_cookie != DHCP_MAGIC_COOKIE) {
        return 0;
    }
    
    // Extract DHCP message type
    size_t len;
    const uint8_t *msg_type = get_dhcp_option(packet->options + 4, 
                                             sizeof(packet->options) - 4,
                                             DHCP_OPTION_MESSAGE_TYPE, &len);
    
    if (!msg_type || len != 1 || *msg_type != message_type) {
        return 0;
    }
    
    return 1;
}

/* DHCP client thread function */
void *dhcp_client_thread(void *arg)
{
    int client_idx = *((int *)arg);
    free(arg);
    
    struct sockaddr_in server_addr, client_addr;
    int sock, broadcast = 1;
    socklen_t addr_len = sizeof(server_addr);
    dhcp_packet packet;
    
    // Create UDP socket
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        die("socket");
    }
    
    // Allow socket to send broadcasts
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
        die("setsockopt - SO_BROADCAST");
    }
    
    // Bind to DHCP client port
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(DHCP_CLIENT_PORT);
    client_addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        die("bind");
    }
    
    // Set up server address (broadcast)
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DHCP_SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_BROADCAST;
    
    // Lock the client state for this thread
    pthread_mutex_lock(&client_mutex);
    uint8_t mac[6];
    memcpy(mac, clients[client_idx].mac, 6);
    uint32_t xid = clients[client_idx].xid;
    pthread_mutex_unlock(&client_mutex);
    
    printf("Client %d (MAC: ", client_idx);
    print_mac(mac);
    printf(", XID: 0x%08x) starting DHCP process\n", xid);
    
    // Create and send DISCOVER
    create_dhcp_discover(&packet, mac, xid);
    
    printf("Client %d sending DHCPDISCOVER\n", client_idx);
    if (sendto(sock, &packet, sizeof(packet), 0, 
               (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        die("sendto - DISCOVER");
    }
    
    // Wait for OFFER
    fd_set readfds;
    struct timeval tv;
    int select_ret;
    int retries = 0;
    int max_retries = 3;
    
    while (retries < max_retries) {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        
        select_ret = select(sock + 1, &readfds, NULL, NULL, &tv);
        
        if (select_ret < 0) {
            die("select");
        } else if (select_ret == 0) {
            printf("Client %d timed out waiting for DHCPOFFER. Retrying...\n", client_idx);
            
            // Retry DISCOVER
            create_dhcp_discover(&packet, mac, xid);
            if (sendto(sock, &packet, sizeof(packet), 0, 
                       (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                die("sendto - DISCOVER retry");
            }
            
            retries++;
            continue;
        }
        
        // Receive DHCP packet
        if (recvfrom(sock, &packet, sizeof(packet), 0, 
                     (struct sockaddr *)&server_addr, &addr_len) < 0) {
            die("recvfrom");
        }
        
        // Check if it's a DHCPOFFER and for our XID
        if (is_dhcp_message(&packet, DHCPOFFER) && packet.xid == xid) {
            break;
        }
        
        // If we got a response but not the right one, wait for more
    }
    
    if (retries >= max_retries) {
        printf("Client %d failed to get DHCPOFFER after %d attempts. Giving up.\n", 
               client_idx, max_retries);
        close(sock);
        pthread_exit(NULL);
    }
    
    // Process OFFER
    pthread_mutex_lock(&client_mutex);
    clients[client_idx].offered_ip = packet.yiaddr;
    
    // Extract server ID
    size_t len;
    const uint8_t *server_id_opt = get_dhcp_option(packet.options + 4, 
                                                  sizeof(packet.options) - 4,
                                                  DHCP_OPTION_SERVER_ID, &len);
    if (server_id_opt && len == 4) {
        memcpy(&clients[client_idx].server_id, server_id_opt, 4);
    }
    pthread_mutex_unlock(&client_mutex);
    
    printf("Client %d received DHCPOFFER for IP %s\n", 
           client_idx, inet_ntoa(*(struct in_addr *)&packet.yiaddr));
    
    // Send REQUEST
    pthread_mutex_lock(&client_mutex);
    create_dhcp_request(&packet, mac, xid, clients[client_idx].offered_ip, 
                        clients[client_idx].server_id);
    pthread_mutex_unlock(&client_mutex);
    
    printf("Client %d sending DHCPREQUEST\n", client_idx);
    if (sendto(sock, &packet, sizeof(packet), 0, 
               (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        die("sendto - REQUEST");
    }
    
    // Wait for ACK
    retries = 0;
    while (retries < max_retries) {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        
        select_ret = select(sock + 1, &readfds, NULL, NULL, &tv);
        
        if (select_ret < 0) {
            die("select");
        } else if (select_ret == 0) {
            printf("Client %d timed out waiting for DHCPACK. Retrying...\n", client_idx);
            
            // Retry REQUEST
            pthread_mutex_lock(&client_mutex);
            create_dhcp_request(&packet, mac, xid, clients[client_idx].offered_ip, 
                                clients[client_idx].server_id);
            pthread_mutex_unlock(&client_mutex);
            
            if (sendto(sock, &packet, sizeof(packet), 0, 
                       (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                die("sendto - REQUEST retry");
            }
            
            retries++;
            continue;
        }
        
        // Receive DHCP packet
        if (recvfrom(sock, &packet, sizeof(packet), 0, 
                     (struct sockaddr *)&server_addr, &addr_len) < 0) {
            die("recvfrom");
        }
        
        // Check if it's ACK or NAK and for our XID
        if ((is_dhcp_message(&packet, DHCPACK) || 
             is_dhcp_message(&packet, DHCPNAK)) && packet.xid == xid) {
            break;
        }
    }
    
    if (retries >= max_retries) {
        printf("Client %d failed to get DHCPACK/NAK after %d attempts. Giving up.\n", 
               client_idx, max_retries);
        close(sock);
        pthread_exit(NULL);
    }
    
    // Process ACK/NAK
    if (is_dhcp_message(&packet, DHCPACK)) {
        pthread_mutex_lock(&client_mutex);
        clients[client_idx].assigned_ip = packet.yiaddr;
        
        // Extract lease time
        const uint8_t *lease_opt = get_dhcp_option(packet.options + 4, 
                                                 sizeof(packet.options) - 4,
                                                 DHCP_OPTION_LEASE_TIME, &len);
        if (lease_opt && len == 4) {
            memcpy(&clients[client_idx].lease_time, lease_opt, 4);
            clients[client_idx].lease_time = ntohl(clients[client_idx].lease_time);
        }
        
        // Extract subnet mask
        const uint8_t *mask_opt = get_dhcp_option(packet.options + 4, 
                                                sizeof(packet.options) - 4,
                                                DHCP_OPTION_SUBNET_MASK, &len);
        if (mask_opt && len == 4) {
            memcpy(&clients[client_idx].subnet_mask, mask_opt, 4);
        }
        
        // Extract router
        const uint8_t *router_opt = get_dhcp_option(packet.options + 4, 
                                                  sizeof(packet.options) - 4,
                                                  DHCP_OPTION_ROUTER, &len);
        if (router_opt && len == 4) {
            memcpy(&clients[client_idx].router_ip, router_opt, 4);
        }
        
        // Extract DNS
        const uint8_t *dns_opt = get_dhcp_option(packet.options + 4, 
                                               sizeof(packet.options) - 4,
                                               DHCP_OPTION_DNS_SERVER, &len);
        if (dns_opt && len == 4) {
            memcpy(&clients[client_idx].dns_ip, dns_opt, 4);
        }
        pthread_mutex_unlock(&client_mutex);
        
        printf("Client %d successfully leased IP %s\n", 
               client_idx, inet_ntoa(*(struct in_addr *)&packet.yiaddr));
        printf("  Subnet mask: %s\n", inet_ntoa(*(struct in_addr *)&clients[client_idx].subnet_mask));
        printf("  Router: %s\n", inet_ntoa(*(struct in_addr *)&clients[client_idx].router_ip));
        printf("  DNS server: %s\n", inet_ntoa(*(struct in_addr *)&clients[client_idx].dns_ip));
        printf("  Lease time: %u seconds\n", clients[client_idx].lease_time);
        
        // If requested, release the IP after a delay
        if (g_release_after > 0) {
            printf("Client %d will release IP in %d seconds\n", client_idx, g_release_after);
            sleep(g_release_after);
            
            pthread_mutex_lock(&client_mutex);
            create_dhcp_release(&packet, mac, xid, clients[client_idx].assigned_ip,
                               clients[client_idx].server_id);
            pthread_mutex_unlock(&client_mutex);
            
            printf("Client %d sending DHCPRELEASE\n", client_idx);
            if (sendto(sock, &packet, sizeof(packet), 0, 
                      (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                die("sendto - RELEASE");
            }
            
            printf("Client %d has released its IP address\n", client_idx);
        }
    } else if (is_dhcp_message(&packet, DHCPNAK)) {
        printf("Client %d received DHCPNAK. Request denied.\n", client_idx);
    }
    
    close(sock);
    pthread_exit(NULL);
}

/* Get MAC address from interface */
int get_interface_mac(const char *interface, uint8_t *mac)
{
    struct ifreq ifr;
    int sock;
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl - SIOCGIFHWADDR");
        close(sock);
        return -1;
    }
    
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return 0;
}

void print_usage(char *prog_name)
{
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -c <count>    Number of clients to simulate (default: 1, max: %d)\n", MAX_CLIENTS);
    printf("  -r <seconds>  Release IP after specified seconds (default: 0 - don't release)\n");
    printf("  -i <interface> Use MAC from this interface as base (default: %s)\n", DEFAULT_INTERFACE);
    printf("  -m <mac>      Use this MAC address as base (format: xx:xx:xx:xx:xx:xx)\n");
    printf("  -h            Display this help message\n");
}

int main(int argc, char *argv[])
{
    int client_count = 1;
    int use_if_mac = 1;
    uint8_t base_mac[6] = {0};
    int c;
    
    while ((c = getopt(argc, argv, "c:r:i:m:h")) != -1) {
        switch (c) {
            case 'c':
                client_count = atoi(optarg);
                if (client_count < 1) client_count = 1;
                if (client_count > MAX_CLIENTS) client_count = MAX_CLIENTS;
                break;
            case 'r':
                g_release_after = atoi(optarg);
                break;
            case 'i':
                strncpy(g_interface, optarg, IFNAMSIZ-1);
                break;
            case 'm':
                use_if_mac = 0;
                if (sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
                          &base_mac[0], &base_mac[1], &base_mac[2],
                          &base_mac[3], &base_mac[4], &base_mac[5]) != 6) {
                    fprintf(stderr, "Invalid MAC address format\n");
                    return 1;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    printf("DHCP Client Tester - Running with %d client(s)\n", client_count);
    
    if (use_if_mac) {
        if (get_interface_mac(g_interface, base_mac) < 0) {
            printf("Failed to get MAC from interface %s, using random MAC\n", g_interface);
            generate_random_mac(base_mac);
        } else {
            printf("Using base MAC from interface %s: ", g_interface);
            print_mac(base_mac);
            printf("\n");
        }
    } else {
        printf("Using provided base MAC: ");
        print_mac(base_mac);
        printf("\n");
    }
    
    srand(time(NULL));
    
    // Initialize client states
    memset(clients, 0, sizeof(clients));
    for (int i = 0; i < client_count; i++) {
        clients[i].active = 1;
        
        // Create a unique MAC based on the base MAC
        memcpy(clients[i].mac, base_mac, 6);
        clients[i].mac[5] += i; // Simple increment for testing
        
        // Generate transaction ID
        clients[i].xid = rand();
    }
    
    // Start client threads
    for (int i = 0; i < client_count; i++) {
        int *client_idx = malloc(sizeof(int));
        if (!client_idx) {
            die("malloc");
        }
        *client_idx = i;
        
        if (pthread_create(&clients[i].thread_id, NULL, dhcp_client_thread, client_idx) != 0) {
            perror("pthread_create");
            free(client_idx);
            continue;
        }
        
        // Small delay between client starts to avoid flooding
        usleep(200000); // 200ms
    }
    
    // Wait for all client threads to complete
    for (int i = 0; i < client_count; i++) {
        if (clients[i].active) {
            pthread_join(clients[i].thread_id, NULL);
        }
    }
    
    // Summary of results
    printf("\n--- DHCP Client Test Results ---\n");
    for (int i = 0; i < client_count; i++) {
        printf("Client %d (MAC: ", i);
        print_mac(clients[i].mac);
        printf("):\n");
        
        if (clients[i].assigned_ip) {
            printf("  Assigned IP: %s\n", inet_ntoa(*(struct in_addr *)&clients[i].assigned_ip));
            printf("  Subnet mask: %s\n", inet_ntoa(*(struct in_addr *)&clients[i].subnet_mask));
            printf("  Router: %s\n", inet_ntoa(*(struct in_addr *)&clients[i].router_ip));
            printf("  DNS server: %s\n", inet_ntoa(*(struct in_addr *)&clients[i].dns_ip));
            
            // Determine subnet based on IP and mask
            uint32_t ip_host = ntohl(clients[i].assigned_ip);
            uint32_t mask = ntohl(clients[i].subnet_mask);
            uint32_t network = ip_host & mask;
            
            char network_str[INET_ADDRSTRLEN];
            struct in_addr network_addr;
            network_addr.s_addr = htonl(network);
            inet_ntop(AF_INET, &network_addr, network_str, INET_ADDRSTRLEN);
            
            printf("  Network: %s/%d\n", network_str, __builtin_popcount(mask));
        } else if (clients[i].offered_ip) {
            printf("  Offered IP: %s (not acknowledged)\n", 
                   inet_ntoa(*(struct in_addr *)&clients[i].offered_ip));
        } else {
            printf("  No IP assigned\n");
        }
    }
    
    return 0;
}
