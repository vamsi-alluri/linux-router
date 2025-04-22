#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include "dhcpd.h"
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "helper.h"

#define BUFLEN 512 // Max length of buffer
#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67
#define MAX_THREADS 20
#define MAX_LEASES 50 
#define MAX_FRAME_LEN 1514  // Maximum Ethernet frame size
#define DHCP_SERVER_INTERFACE "enp0s3"  // Interface for raw packets

// Global variables for DHCP server
dhcp_lease leases[MAX_LEASES];
pthread_mutex_t lease_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t thread_count_mutex = PTHREAD_MUTEX_INITIALIZER;
int thread_count = 0;
int dhcp_socket = -1;
int raw_socket = -1;  // Raw packet socket
unsigned char server_mac[6]; // Server MAC address
uint32_t server_ip = 0;      // Server IP address
volatile int server_running = 1;

typedef struct
{
    struct sockaddr_in client_addr;
    dhcp_packet packet;
    int socket;
    int recv_len;
    int use_raw;         // Flag to indicate if raw socket should be used
    unsigned char client_mac[6]; // For raw socket responses
    int tx_fd;           // Pipe for writing logs back to router
} thread_arg_t;

// Function declarations 
void init_leases();
int add_dhcp_option(uint8_t *options, int offset, uint8_t code, uint8_t len, const uint8_t *data);
const uint8_t *get_dhcp_option(const uint8_t *options, size_t options_len, uint8_t code, size_t *len);
int create_dhcp_packet(dhcp_packet *packet, uint8_t msg_type, uint32_t xid,
                       uint32_t ciaddr, uint32_t yiaddr, const uint8_t *chaddr);
uint32_t allocate_ip(const uint8_t *mac, time_t lease_time);
void *handle_dhcp_request(void *arg);
void listLeases(int tx_fd);
int countActiveLeases();
void die(char *s);

// New function declarations
uint16_t ip_checksum(void *vdata, size_t length);
int get_interface_info(const char *if_name, unsigned char *mac, uint32_t *ip);
int parse_dhcp_packet(const uint8_t *frame, size_t len, dhcp_packet *packet, unsigned char *client_mac);
void send_dhcp_raw(int raw_sock, 
                  const unsigned char *src_mac, 
                  const unsigned char *dst_mac,
                  uint32_t src_ip, uint32_t dst_ip,
                  dhcp_packet *payload, size_t payload_len,
                  int tx_fd);

// Main DHCP service function that communicates with router
void dhcp_main(int rx_fd, int tx_fd) {
    char buffer[256];
    ssize_t count;
    
    // Initialize the DHCP server
    init_leases();
    
    // Get interface info (MAC and IP address)
    if (get_interface_info(DHCP_SERVER_INTERFACE, server_mac, &server_ip) < 0) {
        snprintf(buffer, sizeof(buffer), 
                "Error: Failed to get interface information for %s\n", 
                DHCP_SERVER_INTERFACE);
        write(tx_fd, buffer, strlen(buffer));
        exit(EXIT_FAILURE);
    }
    
    // Create raw packet socket
    if ((raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
        snprintf(buffer, sizeof(buffer), 
                "Error: Failed to create raw socket - %s\n", 
                strerror(errno));
        write(tx_fd, buffer, strlen(buffer));
        exit(EXIT_FAILURE);
    }
    
    // Bind raw socket to interface
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, DHCP_SERVER_INTERFACE, IFNAMSIZ - 1);
    if (setsockopt(raw_socket, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        snprintf(buffer, sizeof(buffer), 
                "Error: Failed to bind raw socket to interface - %s\n", 
                strerror(errno));
        write(tx_fd, buffer, strlen(buffer));
        close(raw_socket);
        exit(EXIT_FAILURE);
    }
    
    // Create UDP socket for DHCP (fallback)
    if ((dhcp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        snprintf(buffer, sizeof(buffer), "Error: Failed to create UDP socket - %s\n", strerror(errno));
        write(tx_fd, buffer, strlen(buffer));
        close(raw_socket);
        exit(EXIT_FAILURE);
    }
    int broadcast_enable = 1;
    if (setsockopt(dhcp_socket, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable)) < 0) {
        snprintf(buffer, sizeof(buffer), "Error: Failed to set broadcast option on UDP socket - %s\n", strerror(errno));
        write(tx_fd, buffer, strlen(buffer));
        close(dhcp_socket);
        close(raw_socket);
        exit(EXIT_FAILURE);
    }


    // Setup socket addressing
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DHCP_SERVER_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    // Bind UDP socket
    if (bind(dhcp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        snprintf(buffer, sizeof(buffer), "Error: Failed to bind UDP socket - %s\n", strerror(errno));
        write(tx_fd, buffer, strlen(buffer));
        close(dhcp_socket);
        close(raw_socket);
        exit(EXIT_FAILURE);
    }
    
    write(tx_fd, "DHCP: Server initialized and ready with raw socket support\n", 58);
    
    fd_set readfds;
    struct timeval timeout;
    
    // Main service loop
    while (server_running) {
        FD_ZERO(&readfds);
        FD_SET(rx_fd, &readfds);
        FD_SET(dhcp_socket, &readfds);
        FD_SET(raw_socket, &readfds);
        
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int max_fd = rx_fd;
        if (dhcp_socket > max_fd) max_fd = dhcp_socket;
        if (raw_socket > max_fd) max_fd = raw_socket;
        
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
        
        // Check for raw packet data
        if (FD_ISSET(raw_socket, &readfds)) {
            uint8_t frame[MAX_FRAME_LEN];
            int recv_len = recvfrom(raw_socket, frame, sizeof(frame), 0, NULL, NULL);

            if (recv_len > 0) {
                dhcp_packet packet;
                unsigned char client_mac[6];
                // only valid DISCOVER/REQUEST
                if (parse_dhcp_packet(frame, recv_len, &packet, client_mac)) {
                    char client_info[100];
                    snprintf(client_info, sizeof(client_info),
                             "DHCP: Received raw packet from MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                             client_mac[0], client_mac[1], client_mac[2],
                             client_mac[3], client_mac[4], client_mac[5]);
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
                        
                        memset(&thread_arg->client_addr, 0, sizeof(thread_arg->client_addr));
                        thread_arg->packet = packet;
                        thread_arg->socket = raw_socket;
                        thread_arg->recv_len = recv_len;
                        thread_arg->use_raw = 1;
                        memcpy(thread_arg->client_mac, client_mac, 6);
                        thread_arg->tx_fd = tx_fd;

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
        
        // Check for regular DHCP client communications (fallback)
        if (FD_ISSET(dhcp_socket, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            dhcp_packet packet;
            
            int recv_len = recvfrom(dhcp_socket, &packet, sizeof(packet), 0, 
                             (struct sockaddr*)&client_addr, &addr_len);
                             
            if (recv_len > 0) {
                char client_info[100];
                snprintf(client_info, sizeof(client_info), 
                         "DHCP: Received packet from %s:%d\n", 
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
                    thread_arg->packet = packet;
                    thread_arg->socket = dhcp_socket;
                    thread_arg->recv_len = recv_len;
                    thread_arg->use_raw = 0;
                    thread_arg->tx_fd = tx_fd;

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
    close(dhcp_socket);
    close(raw_socket);
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

// The rest of your DHCP server implementation
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

void *handle_dhcp_request(void *arg) {
    thread_arg_t *thread_arg = (thread_arg_t *)arg;
    struct sockaddr_in si_other = thread_arg->client_addr;
    dhcp_packet packet = thread_arg->packet;
    int s = thread_arg->socket;
    int use_raw = thread_arg->use_raw;
    int tx_fd = thread_arg->tx_fd;
    unsigned char client_mac[6];
    char log_buffer[256];

    if (use_raw) {
        memcpy(client_mac, thread_arg->client_mac, 6);
        snprintf(log_buffer, sizeof(log_buffer),
                 "[Thread %lu] Handling raw request from MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                 pthread_self(),
                 client_mac[0], client_mac[1], client_mac[2],
                 client_mac[3], client_mac[4], client_mac[5]);
        write(tx_fd, log_buffer, strlen(log_buffer));
    } else {
        snprintf(log_buffer, sizeof(log_buffer),
                 "[Thread %lu] Handling request from %s, port number:%d\n",
                 pthread_self(), inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
        write(tx_fd, log_buffer, strlen(log_buffer));
    }

    // Verify magic cookie
    uint32_t magic_cookie;
    memcpy(&magic_cookie, packet.options, sizeof(magic_cookie));
    magic_cookie = ntohl(magic_cookie);
    if (magic_cookie != DHCP_MAGIC_COOKIE) {
        snprintf(log_buffer, sizeof(log_buffer),
                 "[Thread %lu] Invalid DHCP packet (wrong magic cookie)\n", pthread_self());
        write(tx_fd, log_buffer, strlen(log_buffer));
        free(thread_arg);
        pthread_exit(NULL);
    }

    // Extract DHCP message type option
    size_t opt_len;
    const uint8_t *msg_type_opt = get_dhcp_option(packet.options + 4, sizeof(packet.options) - 4,
                                                 DHCP_OPTION_MESSAGE_TYPE, &opt_len);
    if (!msg_type_opt || opt_len != 1) {
        snprintf(log_buffer, sizeof(log_buffer),
                 "[Thread %lu] Invalid DHCP packet (no message type)\n", pthread_self());
        write(tx_fd, log_buffer, strlen(log_buffer));
        free(thread_arg);
        pthread_exit(NULL);
    }
    uint8_t msg_type = *msg_type_opt;

    switch (msg_type) {
    case DHCPDISCOVER:
    {
        snprintf(log_buffer, sizeof(log_buffer),
                 "[Thread %lu] DHCP DISCOVER received from client\n", pthread_self());
        write(tx_fd, log_buffer, strlen(log_buffer));
        uint32_t new_ip = allocate_ip(use_raw ? client_mac : packet.chaddr, 3600);
        if (!new_ip) {
            snprintf(log_buffer, sizeof(log_buffer),
                     "[Thread %lu] No more IP addresses available\n", pthread_self());
            write(tx_fd, log_buffer, strlen(log_buffer));
            free(thread_arg);
            pthread_exit(NULL);
        }
        // Build DHCP OFFER packet
        dhcp_packet offer;
        int offset = create_dhcp_packet(&offer, DHCPOFFER, packet.xid, 0, new_ip,
                                      use_raw ? client_mac : packet.chaddr);
        uint32_t lease_time = htonl(3600);
        offset = add_dhcp_option(offer.options, offset, DHCP_OPTION_LEASE_TIME, 4, (uint8_t *)&lease_time);
        offset = add_dhcp_option(offer.options, offset, DHCP_OPTION_SERVER_ID, 4, (uint8_t *)&server_ip);
        uint32_t subnet_mask = htonl(0xFFFFFF00); // 255.255.255.0
        offset = add_dhcp_option(offer.options, offset, DHCP_OPTION_SUBNET_MASK, 4, (uint8_t *)&subnet_mask);
        offer.options[offset++] = DHCP_OPTION_END;

        snprintf(log_buffer, sizeof(log_buffer),
                 "[Thread %lu] Sending DHCP OFFER to client with IP: %s\n",
                 pthread_self(), inet_ntoa(*(struct in_addr *)&new_ip));
        write(tx_fd, log_buffer, strlen(log_buffer));

        if (use_raw) {
            // Use broadcast MAC for DHCP offer
            unsigned char broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
            send_dhcp_raw(s, server_mac, broadcast_mac, server_ip, 0xFFFFFFFF, &offer, sizeof(offer), tx_fd);
        } else {
            struct sockaddr_in dest_addr;
            memset(&dest_addr, 0, sizeof(dest_addr));
            dest_addr.sin_family = AF_INET;
            dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
            dest_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST); // 255.255.255.255
            socklen_t dest_len = sizeof(dest_addr);

            if (sendto(s, &offer, sizeof(offer), 0, (struct sockaddr *)&dest_addr, dest_len) == -1) {
                snprintf(log_buffer, sizeof(log_buffer), "sendto() OFFER UDP failed: %s\n", strerror(errno));
                write(tx_fd, log_buffer, strlen(log_buffer));
            }
        }
        break;
    }
    case DHCPREQUEST:
    {
        snprintf(log_buffer, sizeof(log_buffer),
                 "[Thread %lu] DHCP REQUEST received from client\n", pthread_self());
        write(tx_fd, log_buffer, strlen(log_buffer));
        size_t opt_len;
        const uint8_t *req_ip_opt = get_dhcp_option(packet.options + 4, sizeof(packet.options) - 4,
                                                   DHCP_OPTION_REQUESTED_IP, &opt_len);
        uint32_t req_ip = 0;
        if (req_ip_opt && opt_len == 4) {
            memcpy(&req_ip, req_ip_opt, 4);
        } else {
            req_ip = packet.ciaddr;
        }
        
        // Verify if the requested IP is valid
        int found = 0;
        pthread_mutex_lock(&lease_mutex);
        for (int i = 0; i < MAX_LEASES; i++) {
            if (leases[i].active && leases[i].ip == req_ip &&
                memcmp(leases[i].mac, use_raw ? client_mac : packet.chaddr, 6) == 0) {
                found = 1;
                leases[i].lease_start = time(NULL);
                leases[i].lease_end = leases[i].lease_start + 3600;
                break;
            }
        }
        pthread_mutex_unlock(&lease_mutex);
        
        // Build DHCP ACK or NAK packet
        dhcp_packet ack;
        if (found) {
            int offset = create_dhcp_packet(&ack, DHCPACK, packet.xid, 0, req_ip,
                                         use_raw ? client_mac : packet.chaddr);
            snprintf(log_buffer, sizeof(log_buffer),
                     "[Thread %lu] Sending DHCP ACK to client for IP: %s\n",
                     pthread_self(), inet_ntoa(*(struct in_addr *)&req_ip));
            write(tx_fd, log_buffer, strlen(log_buffer));
            uint32_t lease_time = htonl(3600);
            offset = add_dhcp_option(ack.options, offset, DHCP_OPTION_LEASE_TIME, 4, (uint8_t *)&lease_time);
            offset = add_dhcp_option(ack.options, offset, DHCP_OPTION_SERVER_ID, 4, (uint8_t *)&server_ip);
            uint32_t subnet_mask = htonl(0xFFFFFF00);
            offset = add_dhcp_option(ack.options, offset, DHCP_OPTION_SUBNET_MASK, 4, (uint8_t *)&subnet_mask);
            ack.options[offset++] = DHCP_OPTION_END;
            
            if (use_raw) {
                if (packet.ciaddr == 0) {
                    unsigned char broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
                    send_dhcp_raw(s, server_mac, broadcast_mac, server_ip, 0xFFFFFFFF, &ack, sizeof(ack), tx_fd);
                } else {
                    send_dhcp_raw(s, server_mac, client_mac, server_ip, req_ip, &ack, sizeof(ack), tx_fd);
                }
            } else {
                struct sockaddr_in dest_addr;
                memset(&dest_addr, 0, sizeof(dest_addr));
                dest_addr.sin_family = AF_INET;
                dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
                socklen_t dest_len = sizeof(dest_addr);

                if (packet.ciaddr == 0) {
                    dest_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
                } else {
                    dest_addr.sin_addr.s_addr = req_ip;
                }

                if (sendto(s, &ack, sizeof(ack), 0, (struct sockaddr *)&dest_addr, dest_len) == -1) {
                    snprintf(log_buffer, sizeof(log_buffer), "sendto() ACK UDP failed: %s\n", strerror(errno));
                    write(tx_fd, log_buffer, strlen(log_buffer));
                }
            }
        } else {
            int offset = create_dhcp_packet(&ack, DHCPNAK, packet.xid, 0, 0,
                                         use_raw ? client_mac : packet.chaddr);
            snprintf(log_buffer, sizeof(log_buffer),
                     "[Thread %lu] Sending DHCP NAK to client\n", pthread_self());
            write(tx_fd, log_buffer, strlen(log_buffer));
            ack.options[offset++] = DHCP_OPTION_END;
            
            if (use_raw) {
                unsigned char broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
                send_dhcp_raw(s, server_mac, broadcast_mac, server_ip, 0xFFFFFFFF, &ack, sizeof(ack), tx_fd);
            } else {
                struct sockaddr_in dest_addr;
                memset(&dest_addr, 0, sizeof(dest_addr));
                dest_addr.sin_family = AF_INET;
                dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
                dest_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
                socklen_t dest_len = sizeof(dest_addr);

                if (sendto(s, &ack, sizeof(ack), 0, (struct sockaddr *)&dest_addr, dest_len) == -1) {
                    snprintf(log_buffer, sizeof(log_buffer), "sendto() NAK UDP failed: %s\n", strerror(errno));
                    write(tx_fd, log_buffer, strlen(log_buffer));
                }
            }
        }
        break;
    }
    case DHCPRELEASE:
    {
        snprintf(log_buffer, sizeof(log_buffer),
                 "[Thread %lu] DHCP RELEASE received from client\n", pthread_self());
        write(tx_fd, log_buffer, strlen(log_buffer));
        pthread_mutex_lock(&lease_mutex);
        for (int i = 0; i < MAX_LEASES; i++) {
            if (leases[i].active &&
                memcmp(leases[i].mac, use_raw ? client_mac : packet.chaddr, 6) == 0) {
                leases[i].active = 0;
                snprintf(log_buffer, sizeof(log_buffer),
                         "[Thread %lu] Released IP: %s\n",
                         pthread_self(), inet_ntoa(*(struct in_addr *)&leases[i].ip));
                write(tx_fd, log_buffer, strlen(log_buffer));
                break;
            }
        }
        pthread_mutex_unlock(&lease_mutex);
        break;
    }
    default:
        snprintf(log_buffer, sizeof(log_buffer),
                 "[Thread %lu] Unsupported DHCP message type: %d\n", pthread_self(), msg_type);
        write(tx_fd, log_buffer, strlen(log_buffer));
    }

    free(thread_arg);

    pthread_mutex_lock(&thread_count_mutex);
    thread_count--;
    pthread_mutex_unlock(&thread_count_mutex);
    
    pthread_exit(NULL);
}

// Calculate IP header checksum
uint16_t ip_checksum(void *vdata, size_t length) {
    uint8_t *data = (uint8_t *)vdata;
    uint32_t sum = 0;
    size_t i;
    for (i = 0; i < length; i += 2) {
        uint16_t val = 0;
        if (i + 1 < length) {
            val = (data[i] << 8) + data[i + 1];
        } else {
            val = data[i];
        }
        sum += val;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

// Get interface MAC and IP address
int get_interface_info(const char *if_name, unsigned char *mac, uint32_t *ip) {
    int fd;
    struct ifreq ifr;
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    *ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    
    close(fd);
    return 0;
}

// Parse raw packet to extract at least BOOTP + DHCP message-type
int parse_dhcp_packet(const uint8_t *frame, size_t len,
                      dhcp_packet *packet, unsigned char *client_mac)
{
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
        return 0;
    struct ethhdr *eth = (struct ethhdr *)frame;
    if (ntohs(eth->h_proto) != ETH_P_IP) return 0;
    memcpy(client_mac, eth->h_source, 6);

    struct iphdr *ip = (void*)(frame + sizeof(*eth));
    if (ip->protocol != IPPROTO_UDP) return 0;
    size_t ip_hdr_len = ip->ihl * 4;

    struct udphdr *udp = (void*)(frame + sizeof(*eth) + ip_hdr_len);
    if (ntohs(udp->dest) != DHCP_SERVER_PORT) return 0;

    size_t dhcp_offset = sizeof(*eth) + ip_hdr_len + sizeof(*udp);
    size_t avail = len - dhcp_offset;
    if (avail < 4) return 0;

    size_t to_copy = avail < sizeof(dhcp_packet) ? avail : sizeof(dhcp_packet);
    memcpy(packet, frame + dhcp_offset, to_copy);

    uint32_t cookie = ntohl(*(uint32_t*)packet->options);
    if (cookie != DHCP_MAGIC_COOKIE) return 0;

    size_t opt_len;
    const uint8_t *mt = get_dhcp_option(
        packet->options + 4,
        sizeof(packet->options) - 4,
        DHCP_OPTION_MESSAGE_TYPE,
        &opt_len
    );
    if (!mt || opt_len != 1) return 0;
    uint8_t msg_type = *mt;
    if (msg_type != DHCPDISCOVER && msg_type != DHCPREQUEST)
        return 0;

    return 1;
}

// Send DHCP response using raw socket
void send_dhcp_raw(int raw_sock, 
                  const unsigned char *src_mac, 
                  const unsigned char *dst_mac,
                  uint32_t src_ip, uint32_t dst_ip,
                  dhcp_packet *payload, size_t payload_len,
                  int tx_fd) {
    
    uint8_t buf[MAX_FRAME_LEN];
    memset(buf, 0, sizeof(buf));
    char log_buffer[256];

    struct ethhdr *eth = (struct ethhdr *)buf;
    memcpy(eth->h_dest, dst_mac, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_IP);
    
    struct iphdr *ip = (struct iphdr *)(buf + sizeof(*eth));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(*ip) + sizeof(struct udphdr) + payload_len);
    ip->id = htons(rand());
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = src_ip;
    ip->daddr = dst_ip;
    ip->check = ip_checksum(ip, sizeof(*ip));
    
    struct udphdr *udp = (struct udphdr *)(buf + sizeof(*eth) + sizeof(*ip));
    udp->source = htons(DHCP_SERVER_PORT);
    udp->dest = htons(DHCP_CLIENT_PORT);
    udp->len = htons(sizeof(*udp) + payload_len);
    udp->check = 0;
    
    uint8_t* payload_ptr = buf + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
    memcpy(payload_ptr, payload, payload_len);
    
    size_t udp_len = sizeof(*udp) + payload_len;
    size_t pseudo_header_len = 12 + udp_len;
    uint8_t *pseudo_buf = malloc(pseudo_header_len);
    if (pseudo_buf) {
        memcpy(pseudo_buf, &ip->saddr, 4);
        memcpy(pseudo_buf + 4, &ip->daddr, 4);
        pseudo_buf[8] = 0;
        pseudo_buf[9] = ip->protocol;
        uint16_t udp_len_n = htons(udp_len);
        memcpy(pseudo_buf + 10, &udp_len_n, 2);
        memcpy(pseudo_buf + 12, udp, udp_len);
        udp->check = ip_checksum(pseudo_buf, pseudo_header_len);
        if (udp->check == 0) udp->check = 0xFFFF;
        free(pseudo_buf);
    } else {
        udp->check = 0;
        snprintf(log_buffer, sizeof(log_buffer), "DHCP: Warning - Failed to allocate memory for UDP checksum calculation.\n");
        write(tx_fd, log_buffer, strlen(log_buffer));
    }

    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = if_nametoindex(DHCP_SERVER_INTERFACE);
    addr.sll_protocol = htons(ETH_P_IP);
    addr.sll_halen = ETH_ALEN;
    memcpy(addr.sll_addr, dst_mac, 6);

    // Check if it's a broadcast
    unsigned char broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (memcmp(dst_mac, broadcast_mac, 6) == 0 || dst_ip == 0xFFFFFFFF) {
        snprintf(log_buffer, sizeof(log_buffer),
                 "DHCP: Sending RAW broadcast packet (MAC: %02x:%02x:%02x:%02x:%02x:%02x, IP: %s)\n",
                 dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
                 inet_ntoa(*(struct in_addr *)&dst_ip));
        write(tx_fd, log_buffer, strlen(log_buffer));
    } else {
        snprintf(log_buffer, sizeof(log_buffer),
                 "DHCP: Sending RAW unicast packet to MAC: %02x:%02x:%02x:%02x:%02x:%02x, IP: %s\n",
                 dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
                 inet_ntoa(*(struct in_addr *)&dst_ip));
        write(tx_fd, log_buffer, strlen(log_buffer));
    }
    
    ssize_t sent = sendto(raw_sock, buf, sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + payload_len,
          0, (struct sockaddr *)&addr, sizeof(addr));
    
    if (sent < 0) {
        snprintf(log_buffer, sizeof(log_buffer), "DHCP: Failed to send raw packet: %s\n", strerror(errno));
        write(tx_fd, log_buffer, strlen(log_buffer));
    } else {
        snprintf(log_buffer, sizeof(log_buffer), "DHCP: Successfully sent %zd raw bytes\n", sent);
        write(tx_fd, log_buffer, strlen(log_buffer));
    }
}