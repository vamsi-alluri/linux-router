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

#define BUFLEN 512 // Max length of buffer
#define DHCP_CLIENT_PORT 53630
#define DHCP_SERVER_PORT 53629
#define MAX_THREADS 20
#define MAX_LEASES 10  // Define the max number of DHCP leases

// Global variables for DHCP server
dhcp_lease leases[MAX_LEASES];
pthread_mutex_t lease_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t thread_count_mutex = PTHREAD_MUTEX_INITIALIZER;
int thread_count = 0;
int dhcp_socket = -1;
volatile int server_running = 1;

typedef struct
{
    struct sockaddr_in client_addr;
    dhcp_packet packet;
    int socket;
    int recv_len;
} thread_arg_t;

// Function declarations
void init_leases();
int add_dhcp_option(uint8_t *options, int offset, uint8_t code, uint8_t len, const uint8_t *data);
const uint8_t *get_dhcp_option(const uint8_t *options, size_t options_len, uint8_t code, size_t *len);
int create_dhcp_packet(dhcp_packet *packet, uint8_t msg_type, uint32_t xid,
                       uint32_t ciaddr, uint32_t yiaddr, const uint8_t *chaddr);
uint32_t allocate_ip(const uint8_t *mac, time_t lease_time);
void *handle_dhcp_request(void *arg);
int countActiveLeases(void);
void listLeases(int tx_fd);

// Main DHCP service function that communicates with router
void dhcp_main(int rx_fd, int tx_fd) {
    char buffer[256];
    ssize_t count;
    
    // Initialize the DHCP server
    init_leases();
    
    // Create UDP socket for DHCP
    if ((dhcp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        snprintf(buffer, sizeof(buffer), "Error: Failed to create socket - %s\n", strerror(errno));
        write(tx_fd, buffer, strlen(buffer));
        exit(EXIT_FAILURE);
    }
    
    // Setup socket addressing
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DHCP_SERVER_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    // Bind socket
    if (bind(dhcp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        snprintf(buffer, sizeof(buffer), "Error: Failed to bind socket - %s\n", strerror(errno));
        write(tx_fd, buffer, strlen(buffer));
        close(dhcp_socket);
        exit(EXIT_FAILURE);
    }
    
    write(tx_fd, "DHCP: Server initialized and ready\n", 34);
    
    fd_set readfds;
    struct timeval timeout;
    
    // Main service loop
    while (server_running) {
        FD_ZERO(&readfds);
        FD_SET(rx_fd, &readfds);
        FD_SET(dhcp_socket, &readfds);
        
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int max_fd = (rx_fd > dhcp_socket) ? rx_fd : dhcp_socket;
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
        
        // Check for DHCP client communications
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
