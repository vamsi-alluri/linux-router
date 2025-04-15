#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include "dhcpd.h"
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>


#define BUFLEN 512 
#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67
#define MAX_THREADS 20
#define MAX_LEASES 10 
char dhcp_interface[IFNAMSIZ] = "enp0s8";  

dhcp_lease leases[MAX_LEASES];
pthread_mutex_t lease_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t thread_count_mutex = PTHREAD_MUTEX_INITIALIZER;
int thread_count = 0;
int raw_socket = -1;
int fallback_socket = -1;
volatile int server_running = 1;

typedef struct
{
    struct sockaddr_in client_addr;
    dhcp_packet packet;
    int socket;
    int recv_len;
    int is_raw_socket;
} thread_arg_t;

// Function declarations
void init_leases();
int add_dhcp_option(uint8_t *options, int offset, uint8_t code, uint8_t len, const uint8_t *data);
const uint8_t *get_dhcp_option(const uint8_t *options, size_t options_len, uint8_t code, size_t *len);
int create_dhcp_packet(dhcp_packet *packet, uint8_t msg_type, uint32_t xid,
                       uint32_t ciaddr, uint32_t yiaddr, const uint8_t *chaddr);
uint32_t allocate_ip(const uint8_t *mac, time_t lease_time);
void *handle_dhcp_request(void *arg);
int send_dhcp_packet(dhcp_packet *packet, struct sockaddr_in *client_addr, int packet_size, uint8_t *client_mac);
uint16_t checksum(unsigned short *buf, int size);
void die(char *s);
void listLeases(int tx_fd);
int countActiveLeases();
void dhcp_main(int rx_fd, int tx_fd);
void dhcp_set_interface(const char *interface_name);

// Main DHCP service function that communicates with router
void dhcp_main(int rx_fd, int tx_fd) {
    char buffer[256];
    ssize_t count;
    
    init_leases();
    
    // Create raw socket 
    if ((raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
        snprintf(buffer, sizeof(buffer), "Error: Failed to create raw socket - %s\n", strerror(errno));
        write(tx_fd, buffer, strlen(buffer));
        write(tx_fd, "DHCP: Falling back to UDP sockets only (limited RFC 2131 compliance)\n", 68);
    } else {
        // Set interface for raw socket
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, dhcp_interface, IFNAMSIZ-1);
        
        if (ioctl(raw_socket, SIOCGIFINDEX, &ifr) < 0) {
            snprintf(buffer, sizeof(buffer), "Error: Could not get interface index - %s\n", strerror(errno));
            write(tx_fd, buffer, strlen(buffer));
            close(raw_socket);
            raw_socket = -1;
        } else {
            struct sockaddr_ll sll;
            memset(&sll, 0, sizeof(sll));
            sll.sll_family = AF_PACKET;
            sll.sll_ifindex = ifr.ifr_ifindex;
            sll.sll_protocol = htons(ETH_P_IP);
            
            if (bind(raw_socket, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
                snprintf(buffer, sizeof(buffer), "Error: Failed to bind raw socket - %s\n", strerror(errno));
                write(tx_fd, buffer, strlen(buffer));
                close(raw_socket);
                raw_socket = -1;
            } else {
                snprintf(buffer, sizeof(buffer), "DHCP: LPF/%s/%s initialized (raw socket)\n", 
                         dhcp_interface, "00:00:00:00:00:00"); // Placeholder for actual MAC
                write(tx_fd, buffer, strlen(buffer));
            }
        }
    }
    
    // Create fallback UDP socket for DHCP
    if ((fallback_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        snprintf(buffer, sizeof(buffer), "Error: Failed to create fallback socket - %s\n", strerror(errno));
        write(tx_fd, buffer, strlen(buffer));
        if (raw_socket != -1) close(raw_socket);
        exit(EXIT_FAILURE);
    }
    
    // Setup fallback socket addressing
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DHCP_SERVER_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    // Allow socket to reuse address
    int opt = 1;
    if (setsockopt(fallback_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        snprintf(buffer, sizeof(buffer), "Error: Failed to set SO_REUSEADDR - %s\n", strerror(errno));
        write(tx_fd, buffer, strlen(buffer));
    }
    
    // Allow socket to broadcast
    if (setsockopt(fallback_socket, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0) {
        snprintf(buffer, sizeof(buffer), "Error: Failed to set SO_BROADCAST - %s\n", strerror(errno));
        write(tx_fd, buffer, strlen(buffer));
    }
    
    // Bind fallback socket
    if (bind(fallback_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        snprintf(buffer, sizeof(buffer), "Error: Failed to bind fallback socket - %s\n", strerror(errno));
        write(tx_fd, buffer, strlen(buffer));
        if (raw_socket != -1) close(raw_socket);
        close(fallback_socket);
        exit(EXIT_FAILURE);
    }
    
    write(tx_fd, "DHCP: Server initialized and ready\n", 34);
    
    fd_set readfds;
    struct timeval timeout;
    
    // Main service loop
    while (server_running) {
        FD_ZERO(&readfds);
        FD_SET(rx_fd, &readfds);
        FD_SET(fallback_socket, &readfds);
        
        int max_fd = (rx_fd > fallback_socket) ? rx_fd : fallback_socket;
        
        if (raw_socket != -1) {
            FD_SET(raw_socket, &readfds);
            max_fd = (max_fd > raw_socket) ? max_fd : raw_socket;
        }
        
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int select_result = select(max_fd + 1, &readfds, NULL, NULL, &timeout);
        
        if (select_result == -1) {
            if (errno == EINTR) continue;
            snprintf(buffer, sizeof(buffer), "Error: Select failed - %s\n", strerror(errno));
            write(tx_fd, buffer, strlen(buffer));
            break;
        }
        
        // Check for router commands
        if (FD_ISSET(rx_fd, &readfds)) {
            memset(buffer, 0, sizeof(buffer));
            count = read(rx_fd, buffer, sizeof(buffer) - 1);
            
            if (count <= 0) {
                // EOF or error - router closed the pipe
                server_running = 0;
                break;
            }
            
            // Process router command
            if (strcmp(buffer, "shutdown") == 0) {
                write(tx_fd, "DHCP: Shutting down\n", 20);
                server_running = 0;
                break;
            } 
            else if (strcmp(buffer, "status") == 0) {
                char status_msg[256];
                snprintf(status_msg, sizeof(status_msg), 
                         "DHCP: Active leases: %d, Active threads: %d\n", 
                         countActiveLeases(), thread_count);
                write(tx_fd, status_msg, strlen(status_msg));
            }
            else if (strcmp(buffer, "list_leases") == 0) {
                listLeases(tx_fd);
            }
            else {
                char msg[300];
                snprintf(msg, sizeof(msg), "DHCP: Unknown command '%s'\n", buffer);
                write(tx_fd, msg, strlen(msg));
            }
        }
        
        // Check for DHCP client communications on raw socket
        if (raw_socket != -1 && FD_ISSET(raw_socket, &readfds)) {
            uint8_t pkt_buffer[2048]; // Larger buffer for raw packets
            struct sockaddr_ll src_addr;
            socklen_t addr_len = sizeof(src_addr);
            
            int recv_len = recvfrom(raw_socket, pkt_buffer, sizeof(pkt_buffer), 0, 
                                    (struct sockaddr*)&src_addr, &addr_len);
            
            if (recv_len > 0) {
                // Skip Ethernet header (14 bytes) and process IP header to find DHCP payload
                if (recv_len >= 14 + 20) { // Ethernet + min IP header
                    struct iphdr *ip_header = (struct iphdr *)(pkt_buffer + 14);
                    int ip_header_len = ip_header->ihl * 4;
                    
                    // Verify it's UDP and port is DHCP client port
                    if (ip_header->protocol == IPPROTO_UDP) {
                        struct udphdr *udp_header = (struct udphdr *)(pkt_buffer + 14 + ip_header_len);
                        if (ntohs(udp_header->dest) == DHCP_SERVER_PORT) {
                            dhcp_packet *dhcp = (dhcp_packet *)(pkt_buffer + 14 + ip_header_len + 8); // 8 = UDP header size
                            
                            struct sockaddr_in client_addr;
                            memset(&client_addr, 0, sizeof(client_addr));
                            client_addr.sin_family = AF_INET;
                            client_addr.sin_port = udp_header->source;
                            client_addr.sin_addr.s_addr = ip_header->saddr;
                            
                            char client_info[100];
                            snprintf(client_info, sizeof(client_info), 
                                    "DHCP: Received raw packet from %s:%d\n", 
                                    inet_ntoa(client_addr.sin_addr), 
                                    ntohs(client_addr.sin_port));
                            write(tx_fd, client_info, strlen(client_info));
                            
                            // Handle thread creation for DHCP request
                            if (thread_count < MAX_THREADS) {
                                pthread_mutex_lock(&thread_count_mutex);
                                thread_count++;
                                pthread_mutex_unlock(&thread_count_mutex);
                                
                                thread_arg_t *thread_arg = malloc(sizeof(thread_arg_t));
                                if (!thread_arg) {
                                    write(tx_fd, "DHCP: Failed to allocate memory for thread\n", 43);
                                    pthread_mutex_lock(&thread_count_mutex);
                                    thread_count--;
                                    pthread_mutex_unlock(&thread_count_mutex);
                                    continue;
                                }
                                
                                thread_arg->client_addr = client_addr;
                                memcpy(&thread_arg->packet, dhcp, sizeof(dhcp_packet));
                                thread_arg->socket = raw_socket;
                                thread_arg->recv_len = sizeof(dhcp_packet);
                                thread_arg->is_raw_socket = 1;
                                
                                pthread_t thread_id;
                                if (pthread_create(&thread_id, NULL, handle_dhcp_request, thread_arg) != 0) {
                                    write(tx_fd, "DHCP: Failed to create thread\n", 30);
                                    free(thread_arg);
                                    pthread_mutex_lock(&thread_count_mutex);
                                    thread_count--;
                                    pthread_mutex_unlock(&thread_count_mutex);
                                } else {
                                    pthread_detach(thread_id);
                                }
                            } else {
                                write(tx_fd, "DHCP: Maximum threads reached, dropping request\n", 48);
                            }
                        }
                    }
                }
            }
        }
        
        // Check for DHCP client communications on fallback socket
        if (FD_ISSET(fallback_socket, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            dhcp_packet packet;
            
            int recv_len = recvfrom(fallback_socket, &packet, sizeof(packet), 0, 
                                    (struct sockaddr*)&client_addr, &addr_len);
            
            if (recv_len > 0) {
                char client_info[100];
                snprintf(client_info, sizeof(client_info), 
                         "DHCP: Received fallback packet from %s:%d\n", 
                         inet_ntoa(client_addr.sin_addr), 
                         ntohs(client_addr.sin_port));
                write(tx_fd, client_info, strlen(client_info));
                
                if (raw_socket != -1) {
                    continue;  // Discard duplicates if raw socket is active
                }
                
                // Handle thread creation for DHCP request
                if (thread_count < MAX_THREADS) {
                    pthread_mutex_lock(&thread_count_mutex);
                    thread_count++;
                    pthread_mutex_unlock(&thread_count_mutex);
                    
                    thread_arg_t *thread_arg = malloc(sizeof(thread_arg_t));
                    if (!thread_arg) {
                        write(tx_fd, "DHCP: Failed to allocate memory for thread\n", 43);
                        pthread_mutex_lock(&thread_count_mutex);
                        thread_count--;
                        pthread_mutex_unlock(&thread_count_mutex);
                        continue;
                    }
                    
                    thread_arg->client_addr = client_addr;
                    thread_arg->packet = packet;
                    thread_arg->socket = fallback_socket;
                    thread_arg->recv_len = recv_len;
                    thread_arg->is_raw_socket = 0;
                    
                    pthread_t thread_id;
                    if (pthread_create(&thread_id, NULL, handle_dhcp_request, thread_arg) != 0) {
                        write(tx_fd, "DHCP: Failed to create thread\n", 30);
                        free(thread_arg);
                        pthread_mutex_lock(&thread_count_mutex);
                        thread_count--;
                        pthread_mutex_unlock(&thread_count_mutex);
                    } else {
                        pthread_detach(thread_id);
                    }
                } else {
                    write(tx_fd, "DHCP: Maximum threads reached, dropping request\n", 48);
                }
            }
        }
    }
    
    // Cleanup
    if (raw_socket != -1) close(raw_socket);
    close(fallback_socket);
    pthread_mutex_destroy(&lease_mutex);
    pthread_mutex_destroy(&thread_count_mutex);
    write(tx_fd, "DHCP: Service terminated\n", 25);
    close(rx_fd);
    close(tx_fd);
    exit(EXIT_SUCCESS);
}

// Count active leases
int countActiveLeases() {
    int count = 0;
    pthread_mutex_lock(&lease_mutex);
    for (int i = 0; i < MAX_LEASES; i++) {
        if (leases[i].active) {
            count++;
        }
    }
    pthread_mutex_unlock(&lease_mutex);
    return count;
}

// List active leases to router
void listLeases(int tx_fd) {
    char msg[256];
    time_t now = time(NULL);
    
    write(tx_fd, "DHCP: Active leases:\n", 21);
    
    pthread_mutex_lock(&lease_mutex);
    for (int i = 0; i < MAX_LEASES; i++) {
        if (leases[i].active) {
            struct in_addr ip_addr;
            ip_addr.s_addr = leases[i].ip;
            
            snprintf(msg, sizeof(msg), 
                     "  IP: %s, MAC: %02x:%02x:%02x:%02x:%02x:%02x, Expires: %lds\n", 
                     inet_ntoa(ip_addr),
                     leases[i].mac[0], leases[i].mac[1], leases[i].mac[2],
                     leases[i].mac[3], leases[i].mac[4], leases[i].mac[5],
                     leases[i].lease_end - now);
            write(tx_fd, msg, strlen(msg));
        }
    }
    pthread_mutex_unlock(&lease_mutex);
    
    write(tx_fd, "DHCP: End of lease list\n", 24);
}

void die(char *s)
{
    perror(s);
    exit(1);
}

void init_leases()
{
    pthread_mutex_lock(&lease_mutex);
    for (int i = 0; i < MAX_LEASES; i++)
    {
        leases[i].active = 0;
    }
    pthread_mutex_unlock(&lease_mutex);
}

int add_dhcp_option(uint8_t *options, int offset, uint8_t code, uint8_t len, const uint8_t *data)
{
    options[offset++] = code;
    options[offset++] = len;
    memcpy(&options[offset], data, len);
    return offset + len;
}

const uint8_t *get_dhcp_option(const uint8_t *options, size_t options_len, uint8_t code, size_t *len)
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

// Send DHCP packet using raw socket or fallback UDP socket
// Returns the number of bytes sent, or -1 on error
int send_dhcp_packet(dhcp_packet *packet, struct sockaddr_in *client_addr, int packet_size, uint8_t *client_mac) {
    if (raw_socket != -1) {
        // Get interface index 
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, dhcp_interface, IFNAMSIZ-1);
        if (ioctl(raw_socket, SIOCGIFINDEX, &ifr) < 0) {
            perror("send_dhcp_packet: failed to get interface index");
            goto use_fallback;
        }
        
        // Calculate total packet size
        int eth_header_size = sizeof(struct ethhdr);
        int ip_header_size = sizeof(struct iphdr);
        int udp_header_size = sizeof(struct udphdr);
        int total_size = eth_header_size + ip_header_size + udp_header_size + packet_size;
        
        // Allocate buffer for the full packet
        uint8_t *buffer = malloc(total_size);
        if (!buffer) {
            perror("send_dhcp_packet: failed to allocate memory");
            goto use_fallback;
        }
        memset(buffer, 0, total_size);
        
        // Set up Ethernet header
        struct ethhdr *eth = (struct ethhdr *)buffer;
        
        // Use broadcast MAC if client_mac is null or all zeros
        if (client_mac == NULL || (client_mac[0] == 0 && client_mac[1] == 0 && 
            client_mac[2] == 0 && client_mac[3] == 0 && client_mac[4] == 0 && client_mac[5] == 0)) {
            // Broadcast MAC
            memset(eth->h_dest, 0xFF, ETH_ALEN);
        } else {
            // Client MAC
            memcpy(eth->h_dest, client_mac, ETH_ALEN);
        }
        
        // Get our interface MAC address
        if (ioctl(raw_socket, SIOCGIFHWADDR, &ifr) < 0) {
            perror("send_dhcp_packet: failed to get interface MAC");
            free(buffer);
            goto use_fallback;
        }
        memcpy(eth->h_source, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        eth->h_proto = htons(ETH_P_IP);
        
        // Set up IP header
        struct iphdr *ip = (struct iphdr *)(buffer + eth_header_size);
        ip->version = 4;
        ip->ihl = 5; // 5 * 4 bytes = 20 bytes (no options)
        ip->tos = 0;
        ip->tot_len = htons(ip_header_size + udp_header_size + packet_size);
        ip->id = htons(rand() & 0xFFFF);  // Random ID
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP;
        ip->check = 0;  // Will calculate later
        
        // Get our interface IP address
        if (ioctl(raw_socket, SIOCGIFADDR, &ifr) < 0) {
            perror("send_dhcp_packet: failed to get interface IP");
            free(buffer);
            goto use_fallback;
        }
        struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
        ip->saddr = sin->sin_addr.s_addr;
        
        // Set destination IP - either unicast or broadcast based on client state
        if (client_addr->sin_addr.s_addr != INADDR_ANY && client_addr->sin_addr.s_addr != INADDR_BROADCAST) {
            // Use client IP if it's valid (not 0.0.0.0 or 255.255.255.255)
            ip->daddr = client_addr->sin_addr.s_addr;
        } else {
            ip->daddr = INADDR_BROADCAST;
        }
        
        // Calculate IP checksum
        ip->check = checksum((unsigned short *)ip, ip_header_size);
        
        // Set up UDP header
        struct udphdr *udp = (struct udphdr *)(buffer + eth_header_size + ip_header_size);
        udp->source = htons(DHCP_SERVER_PORT);
        udp->dest = htons(DHCP_CLIENT_PORT);
        udp->len = htons(udp_header_size + packet_size);
        udp->check = 0;  // Will calculate later
        
        // Copy DHCP packet data
        memcpy(buffer + eth_header_size + ip_header_size + udp_header_size, packet, packet_size);
        
        // Calculate UDP checksum (optional but recommended)
        // Create pseudo-header for checksum calculation
        struct {
            uint32_t src_addr;
            uint32_t dst_addr;
            uint8_t zeros;
            uint8_t protocol;
            uint16_t length;
        } __attribute__((packed)) pseudo_header;
        
        pseudo_header.src_addr = ip->saddr;
        pseudo_header.dst_addr = ip->daddr;
        pseudo_header.zeros = 0;
        pseudo_header.protocol = IPPROTO_UDP;
        pseudo_header.length = udp->len;
        
        // Calculate checksum over pseudo-header and UDP datagram
        uint8_t *udp_data = buffer + eth_header_size + ip_header_size;
        int udp_data_len = ntohs(udp->len);
        
        uint32_t sum = 0;
        sum += checksum((unsigned short *)&pseudo_header, sizeof(pseudo_header));
        sum += checksum((unsigned short *)udp_data, udp_data_len);
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);
        udp->check = (uint16_t)~sum;
        if (udp->check == 0) udp->check = 0xFFFF;  // 0 is reserved for "no checksum"
        
        // Set up sockaddr_ll for sending
        struct sockaddr_ll dest;
        memset(&dest, 0, sizeof(dest));
        dest.sll_family = AF_PACKET;
        dest.sll_protocol = htons(ETH_P_IP);
        dest.sll_ifindex = ifr.ifr_ifindex;
        dest.sll_halen = ETH_ALEN;
        
        if (client_mac == NULL || (client_mac[0] == 0 && client_mac[1] == 0 && 
            client_mac[2] == 0 && client_mac[3] == 0 && client_mac[4] == 0 && client_mac[5] == 0)) {
            // Broadcast MAC
            memset(dest.sll_addr, 0xFF, ETH_ALEN);
        } else {
            // Client MAC
            memcpy(dest.sll_addr, client_mac, ETH_ALEN);
        }
        
        // Send the packet
        int result = sendto(raw_socket, buffer, total_size, 0, (struct sockaddr*)&dest, sizeof(dest));
        
        free(buffer);
        
        if (result < 0) {
            perror("send_dhcp_packet: raw socket send failed");
            goto use_fallback;
        }
        
        return result;
    }
    
use_fallback:
    // Use fallback socket for all cases when raw socket is not available or fails
    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(DHCP_CLIENT_PORT);
    
    // Determine if we should use broadcast or unicast
    if (client_addr->sin_addr.s_addr != INADDR_ANY && client_addr->sin_addr.s_addr != INADDR_BROADCAST) {
        // Client has an IP address, use it
        broadcast_addr.sin_addr.s_addr = client_addr->sin_addr.s_addr;
    } else {
        // Use broadcast address
        broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;
    }
    
    return sendto(fallback_socket, packet, packet_size, 0, 
                 (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
}

// Helper function to calculate IP/UDP checksums
uint16_t checksum(unsigned short *buf, int size) {
    unsigned long sum = 0;
    
    while (size > 1) {
        sum += *buf++;
        size -= 2;
    }
    
    if (size == 1) {
        sum += *(unsigned char*)buf;
    }
    
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    
    return (uint16_t)~sum;
}

// Function to set the DHCP interface
void dhcp_set_interface(const char *interface_name) {
    if (interface_name && strlen(interface_name) < IFNAMSIZ) {
        strncpy(dhcp_interface, interface_name, IFNAMSIZ-1);
        dhcp_interface[IFNAMSIZ-1] = '\0'; // Ensure null termination
    }
}