#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>          // For address conversion.
#include <stdarg.h>             // For va_start
#include <errno.h>
#include <inttypes.h>           // For printing hex code of uint16_t.

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <time.h>
#include "packet_helper.h"
#include "natd.h"
#include "uthash.h"


#define BUFFER_SIZE 1518                // To cover the whole ethernet frame.
#define START_PORT 60000
#define DEFAULT_LAN_IFACE "enp0s8"      // Configurable by command.
#define DEFAULT_WAN_IFACE "enp0s3"      // Configurable by command.
#define MAX_LOG_SIZE 5 * 1024 * 1024    // 5MB default
#define DEFAULT_LOG_PATH "/tmp/logs/nat_log.txt"

#define TCP_IP_TYPE 6
#define UDP_IP_TYPE 17
#define ICMP_IP_TYPE 1
#define IPV4_ETH_TYPE 2048              // 0x0800 in decimal.
#define ARP_ETH_TYPE 2054               // 0x0806 in decimal.
#define NAT_TABLE_SIZE 4096             // Power of 2 for bitmask optimization  
#define MASK 0xFFFFFF00
#define TCP_TIMEOUT_DEFAULT 4 * 60 * 60 // 4 hrs in seconds.
#define UDP_TIMEOUT_DEFAULT 5 * 60      // 5 min in seconds.
#define ICMP_TIMEOUT_DEFAULT 60         // 1 min.
#define CLEANUP_INTERVAL_DEFAULT 5 * 60         // 5 min in seconds.
#define ARPOP_REQUEST 1
#define ARPOP_REPLY   2

// Reserved ports (Don't use these for assigning outbound ports to WAN.)
// 22 to ssh into the linux machine.
// 53 to use DNS.
// 80 and 8080 for http
// 443 for https.
// If there is something on these ports, pass through if it exists in the 


// Global variables:
static int lan_raw, wan_raw, rx_fd, tx_fd;
static char *log_file_path = DEFAULT_LOG_PATH;
static uint8_t wan_machine_mac[6], lan_machine_mac[6], wan_gateway_mac[6];
static uint32_t wan_machine_ip, lan_machine_ip, wan_gateway_ip;
static char wan_machine_ip_str[INET_ADDRSTRLEN];
static char lan_machine_ip_str[INET_ADDRSTRLEN];
static int verbose, tcp_timeout = TCP_TIMEOUT_DEFAULT, udp_timeout = UDP_TIMEOUT_DEFAULT, icmp_timeout = ICMP_TIMEOUT_DEFAULT, cleanup_interval = CLEANUP_INTERVAL_DEFAULT;
static uint8_t BROADCAST_MAC[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
static struct arp_cache_entry *arp_cache = NULL;
static struct arp_pending_packet *pending_packets = NULL;

// Explicit Function Declarations:
int init_socket(char *iface_name);
void append_ln_to_log_file_nat(const char *msg, ...);
void append_ln_to_log_file_nat_verbose(const char *msg, ...);
static void vappend_ln_to_log_file_nat(const char *msg, va_list args);
uint16_t allocate_port(uint8_t protocol);


// NAT table:
struct nat_entry{
    uint32_t orig_ip;           // LAN IP
    uint16_t orig_port;         // LAN port/ICMP ID
    uint32_t trans_ip;          // Translated IP - NAT gateway IP
    uint16_t trans_port;        // Translated port/ICMP ID - Random port.
    uint8_t protocol;           // TCP (6), UDP (17), ICMP (1)
    time_t last_used;           // Used for timeout calculations.
    uint16_t custom_timeout;    // Timeout in seconds - Used in overriding situations - they're read through config.
};


typedef struct nat_bucket {  
    struct nat_entry *entry;  
    struct nat_bucket *next;  
} nat_bucket;  

nat_bucket *nat_table[NAT_TABLE_SIZE];  

/// NAT table functions:
uint32_t hash_key(uint32_t ip, uint16_t port, uint8_t proto) {  
    uint32_t h = ip ^ (port << 16) ^ proto;  
    h = ((h >> 16) ^ h) * 0x45d9f3b;  
    h = ((h >> 16) ^ h) * 0x45d9f3b;  
    return (h >> 16) ^ h;  
}  
struct nat_entry* find_by_original(struct nat_entry *details) {
    if (!details) return NULL;

    char src_ip_str[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &details->orig_ip, src_ip_str, INET_ADDRSTRLEN);

    append_ln_to_log_file_nat("Find by: %s:%u", src_ip_str, details->orig_port);
    
    uint32_t h = hash_key(details->orig_ip, details->orig_port, details->protocol) % NAT_TABLE_SIZE;
    for (struct nat_bucket *b = nat_table[h]; b != NULL; b = b->next) {
        if (b->entry->orig_ip == details->orig_ip &&
            b->entry->orig_port == details->orig_port &&
            b->entry->protocol == details->protocol) 
        {
            b->entry->last_used = time(NULL);

            
            char ip_str[INET_ADDRSTRLEN];
            struct in_addr addr = {.s_addr = b->entry->trans_ip};
            inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);

            append_ln_to_log_file_nat("Found entry: %s:%u", ip_str, b->entry->trans_port);
            return b->entry;
        }
    }
    return NULL;
}

// Not sure yet why I created this function. We'll get to know as I implement WAN to LAN comms.
struct nat_entry* find_by_translated(struct nat_entry *details) {  
    if (!details) return NULL;
    
    uint32_t h = hash_key(details->trans_ip, details->trans_port, details->protocol) % NAT_TABLE_SIZE;  
    for (struct nat_bucket *b = nat_table[h]; b != NULL; b = b->next) {  
        if (b->entry->trans_ip == details->trans_ip &&  
            b->entry->trans_port == details->trans_port &&  
            b->entry->protocol == details->protocol) {  
            b->entry->last_used = time(NULL);  
            return b->entry;  
        }  
    }  
    return NULL;
}

// Entry enrichment function using structs
struct nat_entry* enrich_entry(struct nat_entry *details) {  
    if (!details) return NULL;


    // Try to find existing entry first
    struct nat_entry *existing = find_by_original(details);

    // Temporarily disabling NAT look up.
    // existing = NULL
    if (existing) {
        char ip_str[INET_ADDRSTRLEN];
        struct in_addr addr = {.s_addr = existing->trans_ip};
        inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
        
        append_ln_to_log_file_nat("NAT: Existing entry found: %s:%u -> %s:%u",
                                inet_ntoa(*(struct in_addr*)&details->orig_ip),
                                details->orig_port,
                                ip_str,
                                existing->trans_port);
        return existing;
    }

    // Create new entry
    struct nat_entry *new_entry = malloc(sizeof(struct nat_entry));
    if (!new_entry) {
        append_ln_to_log_file_nat("NAT: Failed to allocate new entry");
        return NULL;
    }

    *new_entry = (struct nat_entry){
        .orig_ip = details->orig_ip,
        .orig_port = details->orig_port,
        .trans_ip = wan_machine_ip,
        .trans_port = allocate_port(details->protocol),
        .protocol = details->protocol,
        .last_used = time(NULL)
    };

    // Log creation    
    char src_ip_str[INET_ADDRSTRLEN], wan_ip_str[INET_ADDRSTRLEN];
          
    inet_ntop(AF_INET, &new_entry->orig_ip, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &new_entry->trans_ip, wan_ip_str, INET_ADDRSTRLEN);
    
    append_ln_to_log_file_nat("NAT: Created new entry: %s:%u translates as %s:%u",
                            src_ip_str,
                            new_entry->orig_port,
                            wan_ip_str,
                            new_entry->trans_port);

    // Add to hash table
    uint32_t h = hash_key(details->orig_ip, details->orig_port, details->protocol) % NAT_TABLE_SIZE;
    struct nat_bucket *new_bucket = malloc(sizeof(struct nat_bucket));
    if (!new_bucket) {
        free(new_entry);
        append_ln_to_log_file_nat("NAT: Failed to allocate new bucket");
        return NULL;
    }

    new_bucket->entry = new_entry;
    new_bucket->next = nat_table[h];
    nat_table[h] = new_bucket;


    return new_entry;
}

// NAT table cleanup.
void nat_table_cleanup() {  
    time_t now = time(NULL);
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {  
        struct nat_bucket **prev = &nat_table[i];  
        while (*prev != NULL) {  
            struct nat_bucket *curr = *prev;  
            // Different timeout based on the protocol.
            int timeout_for_this_entry = 5;
            if (curr->entry->protocol == IPPROTO_TCP) {  
                timeout_for_this_entry = tcp_timeout;  
            } else if (curr->entry->protocol == IPPROTO_UDP) {  
                timeout_for_this_entry = udp_timeout;  
            } else if (curr->entry->protocol == IPPROTO_ICMP) {  
                timeout_for_this_entry = icmp_timeout;  
            } else {  
                timeout_for_this_entry = 0;  // Unknown protocol, this shouldn't have happened, remove from the table.  
            }
            if (now - curr->entry->last_used > timeout_for_this_entry) {
                *prev = curr->next;  
                append_ln_to_log_file_nat("Removing entry which was last used on %d.", curr->entry->last_used);
                free(curr->entry);  
                free(curr);  
            } else {  
                prev = &curr->next;  
            }  
        }  
    }  
}

/// ARP:

#define ARP_CACHE_TIMEOUT 300  // 5 minutes
#define MAX_BUFFERED_PACKETS 64

typedef enum { INBOUND, OUTBOUND } packet_direction_t;

struct arp_cache_entry {
    uint32_t ip;
    uint8_t mac[6];
    time_t last_updated;
    UT_hash_handle hh;
};

struct arp_pending_packet {
    uint8_t *data;
    size_t len;
    uint32_t target_ip;
    packet_direction_t direction;
    time_t queued_at;
    UT_hash_handle hh;
};

void arp_cache_update(uint32_t ip, uint8_t *mac) {
    struct arp_cache_entry *entry;
    HASH_FIND_INT(arp_cache, &ip, entry);
    
    if (!entry) {
        entry = malloc(sizeof(*entry));
        entry->ip = ip;  // Set the IP for the new entry
        HASH_ADD_INT(arp_cache, ip, entry);
    }
    memcpy(entry->mac, mac, 6);
    entry->last_updated = time(NULL);
}

void buffer_packet(uint8_t *data, size_t len, uint32_t target_ip, packet_direction_t dir) {
    append_ln_to_log_file_nat("Buffering packet for target IP: %s", inet_ntoa(*(struct in_addr *)&target_ip));
    struct arp_pending_packet *pkt = malloc(sizeof(*pkt));
    pkt->data = malloc(len);
    memcpy(pkt->data, data, len);
    pkt->len = len;
    pkt->target_ip = target_ip;
    pkt->direction = dir;
    pkt->queued_at = time(NULL);
    HASH_ADD_INT(pending_packets, target_ip, pkt);
}

void send_arp_request(uint32_t target_ip, packet_direction_t direction) {
    // Allocate space for full Ethernet frame with ARP payload
    size_t frame_size = sizeof(struct ethernet_header) + sizeof(struct arp_header);
    uint8_t *frame = malloc(frame_size);
    
    // Build Ethernet header
    struct ethernet_header *eth = (struct ethernet_header *)frame;
    eth->type = htons(ETH_P_ARP);
    memcpy(eth->dst_mac, BROADCAST_MAC, 6);
    memcpy(eth->src_mac, (direction == OUTBOUND) ? wan_machine_mac : lan_machine_mac, 6);

    // Build ARP header
    struct arp_header *arp = (struct arp_header *)(frame + sizeof(struct ethernet_header));
    *arp = (struct arp_header){
        .hardware_type = htons(1),          // Ethernet
        .protocol_type = htons(ETH_P_IP),   // IPv4
        .hardware_len = 6,
        .protocol_len = 4,
        .operation = htons(ARPOP_REQUEST),  // Use standard constant
        .sender_ip = (direction == OUTBOUND) ? wan_machine_ip : lan_machine_ip,
        .target_ip = target_ip
    };
    
    memcpy(arp->sender_mac, (direction == OUTBOUND) ? wan_machine_mac : lan_machine_mac, 6);
    memset(arp->target_mac, 0, 6);

    // Send raw frame
    send_raw_frame(BROADCAST_MAC, ETH_P_ARP, frame, frame_size, direction);
    
    // Log with proper IP formatting
    struct in_addr target_addr = {.s_addr = target_ip};
    append_ln_to_log_file_nat("Sent ARP request for %s via %s interface",
                        inet_ntoa(target_addr),
                        (direction == OUTBOUND) ? "WAN" : "LAN");
    
    free(frame);  // Clean up allocated memory
}


void handle_arp_reply(uint8_t *frame, ssize_t len) {

    const struct arp_header *arp = extract_arp_header_from_ethernet_frame(frame);
    
    // Update cache
    arp_cache_update(arp->sender_ip, (uint8_t *)arp->sender_mac);
    
    append_ln_to_log_file_nat("Handling ARP reply...");
    append_ln_to_log_file_nat("Sender IP: %s", inet_ntoa(*(struct in_addr *)&arp->sender_ip));
    append_ln_to_log_file_nat("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                            arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2],
                            arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);
    
    // Process buffered packets
    append_ln_to_log_file_nat("Processing buffered packets...");
    struct arp_pending_packet *pkt, *tmp;
    HASH_FIND_INT(pending_packets, &arp->sender_ip, pkt);
    
    while(pkt) {
        struct ethernet_header *eth_header = (struct ethernet_header *)pkt->data;
        memcpy(eth_header->dst_mac, arp->sender_mac, 6);
        append_ln_to_log_file_nat("Sending buffered packet to %s", inet_ntoa(*(struct in_addr *)&arp->sender_ip));

        send_raw_frame(arp->sender_mac, ETH_P_IP, pkt->data, pkt->len, pkt->direction);
        
        tmp = pkt;  // Save current packet before deletion
        HASH_DEL(pending_packets, pkt);
        free(tmp->data);
        free(tmp);
        
        // Look for more packets for this IP
        HASH_FIND_INT(pending_packets, &arp->sender_ip, pkt);
    }
}

/// End of ARP



/// Utility Functions:

int is_local_bound_packet(uint32_t dst_ip, uint32_t src_ip) {
    uint32_t src_ip_host = ntohl(src_ip);
    uint32_t dst_ip_host = ntohl(dst_ip);
    int is_local = (dst_ip_host & MASK) == (src_ip_host & MASK);
    // append_ln_to_log_file_nat("NAT: dst_ip & 0xFFFFFF00: %d", (dst_ip_host & 0xFFFFFF00));
    // append_ln_to_log_file_nat("NAT: src_ip & 0xFFFFFF00: %d", (src_ip_host & 0xFFFFFF00));
    return is_local;
}

// Checks if src MAC address is of the WAN iface.
int is_packet_outgoing(struct ethernet_header *eth_header){
    // wan_machine_mac is loaded at the start of the application.
    return memcmp(eth_header->src_mac, wan_machine_mac, 6) == 0;
}

// Allocates a port incrementally.
uint16_t allocate_port(uint8_t protocol) {  
    static uint16_t next_port = 32768;      // Start in ephemeral range (32768-60999)  
    uint16_t candidate = next_port++;  

    // Check for port collision  
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {  
        for (struct nat_bucket *b = nat_table[i]; b != NULL; b = b->next) {  
            if (b->entry->trans_port == candidate &&  
                b->entry->protocol == protocol) {  
                candidate = next_port++;    // Collision → try next port  
                i = -1;                     // Restart search  
                break;
            }
        }
    }
    append_ln_to_log_file_nat("Allocated port: %u", candidate);

    if (next_port > 60999) next_port = 32768; 
    return candidate;  
}  

void get_machine_mac(const char *iface, char* mac) {  
    int fd = socket(AF_INET, SOCK_DGRAM, 0);  
    struct ifreq ifr;  

    strncpy(ifr.ifr_name, iface, IFNAMSIZ);  
    ioctl(fd, SIOCGIFHWADDR, &ifr);  
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);  

    close(fd);  
}

uint32_t get_default_gateway_ip(const char *interface) {
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char iface[32];
        unsigned long dest, gateway;
        if (sscanf(line, "%31s %lx %lx", iface, &dest, &gateway) == 3) {
            if (dest == 0 && strcmp(iface, interface) == 0) {
                fclose(f);
                // Convert from little-endian to network byte order
                return htonl(gateway);
            }
        }
    }
    fclose(f);
    return 0; // 0 means not found
}


// Sends binary content to router.
void send_to_router(unsigned char *msg, int msg_len) {
    write(tx_fd, msg, msg_len);
}

char* time_to_fstr(time_t _time, char buffer[26]){
    strftime(*buffer, 26, "%Y-%m-%d %H:%M:%S", localtime(&_time));
}

static void clear_log_file() {
    FILE *log_file = fopen(log_file_path, "w");
    if (log_file) {
        fprintf(log_file, "\n\n");
        fclose(log_file);
        append_ln_to_log_file_nat("Log file cleared.");
    }
}

static void vappend_ln_to_log_file_nat(const char *msg, va_list args) {

    // Clean up the log file if the size is more than 10 MB.
    va_list argp;  

    FILE *log_file = fopen(log_file_path, "r");
    if (log_file) {
        fseek(log_file, 0, SEEK_END);
        long file_size = ftell(log_file);
        fclose(log_file);
        
        if (file_size > MAX_LOG_SIZE) {
            clear_log_file();
            append_ln_to_log_file_nat("Log file size exceeded %d bytes.", MAX_LOG_SIZE);
        }
    }

    if (msg == NULL || strcmp("", msg) == 0){
        log_file = fopen(log_file_path, "a");
        if (log_file) {
            fprintf(log_file, "\n");
            fclose(log_file);
        }
        return;
    }

    time_t now = time(NULL);
    char buffer[26];
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    log_file = fopen(log_file_path, "a");
    if (log_file) {
        fprintf(log_file, "[%s] ", buffer);
        vfprintf(log_file, msg, args);
        fprintf(log_file, "\n");
        fclose(log_file);
    }
}

void append_ln_to_log_file_nat(const char *msg, ...) {
    
    va_list args;
    va_start(args, msg);
    vappend_ln_to_log_file_nat(msg, args);
    va_end(args);
}

void append_ln_to_log_file_nat_verbose(const char *msg, ...) {
    if (verbose != 1) return;

    va_list args;
    va_start(args, msg);
    vappend_ln_to_log_file_nat(msg, args);
    va_end(args);
}

int get_machine_ip(const char *iface, char *gateway_ip, size_t size) {

    
    int temp_sock;  // Temporary socket for IP lookup
    struct ifreq ifr;

    // Get IP address using a temporary socket
    if((temp_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        append_ln_to_log_file_nat("Temp socket creation failed on iface %s.", iface);
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if(ioctl(temp_sock, SIOCGIFADDR, &ifr) < 0) {
        append_ln_to_log_file_nat("IP address retrieval failed on iface %s. Continuing without it.", iface);
        close(temp_sock);
    }
    
    // Store IP
    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    uint32_t ip_buffer = ip_addr->sin_addr.s_addr;
    
    inet_ntop(AF_INET, &ip_buffer, gateway_ip, INET_ADDRSTRLEN);
    close(temp_sock);

}


// This should be called once at the start of the program.
void init_and_load_configurations() {
       
    append_ln_to_log_file_nat_verbose("Verbose mode enabled.");
    
    // Load defaults:

    // Interface and socket setup
    wan_raw = init_socket(DEFAULT_WAN_IFACE);
    lan_raw = init_socket(DEFAULT_LAN_IFACE);
    get_machine_mac(DEFAULT_WAN_IFACE, wan_machine_mac);        // Assigns to wan_machine_mac.
    get_machine_mac(DEFAULT_WAN_IFACE, lan_machine_mac);        // Assigns to lan_machine_mac.
    
    wan_gateway_ip = htonl(get_default_gateway_ip(DEFAULT_WAN_IFACE));
    append_ln_to_log_file_nat("[Info] WAN gateway IP: %s", inet_ntoa(*(struct in_addr *)&wan_gateway_ip));
    send_arp_request(wan_gateway_ip, OUTBOUND); // Send ARP request to get MAC address of the gateway. This will arrive on handle inbound.
    
    // Obsolete: I'm planning on using an ARP table to get MAC from IP.
    // load_wan_next_hop_mac(DEFAULT_WAN_IFACE);

    get_machine_ip(DEFAULT_WAN_IFACE, wan_machine_ip_str, sizeof(wan_machine_ip_str));
    get_machine_ip(DEFAULT_LAN_IFACE, lan_machine_ip_str, sizeof(lan_machine_ip_str));
    
    struct in_addr addr;
    inet_pton(AF_INET, wan_machine_ip_str, &addr);
    wan_machine_ip = addr.s_addr;

    

    append_ln_to_log_file_nat("[info] WAN iface Machine IP: %s", wan_machine_ip_str);
    append_ln_to_log_file_nat("[info] LAN iface Machine IP: %s", lan_machine_ip_str);
    
    append_ln_to_log_file_nat("[info] WAN and LAN interfaces ready.");
    append_ln_to_log_file_nat(NULL);

    // If failed, throw a critical error to router and log it.
}


/// Packet processing:

int init_socket(char *iface_name){
    
    struct sockaddr_ll saddr;
    struct ifreq ifr;
    int raw_sock;

    if((raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        append_ln_to_log_file_nat("NAT: Socket creation failed.");

        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
    if(ioctl(raw_sock, SIOCGIFINDEX, &ifr) < 0) {
        append_ln_to_log_file_nat("NAT: Interface config failed.");
        close(raw_sock);
        exit(EXIT_FAILURE);
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_ifindex = ifr.ifr_ifindex;
    saddr.sll_protocol = htons(ETH_P_ALL);
    
    if(bind(raw_sock, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        append_ln_to_log_file_nat("NAT: Bind failed.");
        close(raw_sock);
        exit(EXIT_FAILURE);
    }

    // Promiscuous mode
    if(ioctl(raw_sock, SIOCGIFFLAGS, &ifr) != -1) {
        ifr.ifr_flags |= IFF_PROMISC;
        ioctl(raw_sock, SIOCSIFFLAGS, &ifr);
    }

    return raw_sock;
}

void send_raw_frame(uint8_t *dest_mac, uint16_t protocol, void *data, size_t len, packet_direction_t direction) {
    struct sockaddr_ll dest_addr = {0};
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(protocol);
    dest_addr.sll_halen = ETH_ALEN;
    memcpy(dest_addr.sll_addr, dest_mac, ETH_ALEN);

    // Interface selection
    const char *ifname = (direction == INBOUND) ? DEFAULT_LAN_IFACE : DEFAULT_WAN_IFACE;
    dest_addr.sll_ifindex = if_nametoindex(ifname);

    // MAC assignment
    uint8_t *src_mac = (direction == INBOUND) ? lan_machine_mac : wan_machine_mac;
    memcpy(((struct ethernet_header*)data)->src_mac, src_mac, 6);

    // Socket selection
    int sock = (direction == INBOUND) ? lan_raw : wan_raw;
    sendto(sock, data, len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
}

// Flow: From LAN to WAN => 192.168.20.2 -> 172.217.215.102
void handle_outbound_packet(unsigned char *buffer, ssize_t len) {
    
    // Get ethernet frame and header.
    struct raw_ethernet_frame *eth_frame = extract_ethernet_frame(buffer);
    struct ethernet_header *eth_header = &eth_frame->header;

    append_ln_to_log_file_nat("Handle outbound: Ethernet header type: %u", ntohs(eth_header->type));
    
    
    if(ntohs(eth_header->type) != IPV4_ETH_TYPE) return;  // Anything other than IPv4 SHALL NOT PASS!
    
    // Get IP packet and header.
    struct ipv4_packet *ip_packet = extract_ipv4_packet_from_eth_payload(&eth_frame->payload);
    struct ipv4_header *ip_header = &ip_packet->header;
    
    if(ip_header->version != 4) return;                   // Anything other than IPv4 SHALL NOT PASS!
    
    // Copy src address and dsr address.
    uint16_t dport;
    uint32_t src_ip = ip_header->saddr;
    uint32_t dst_ip = ip_header->daddr;

    // Is destination IP in the same subnet? Don't process it.
    if (is_local_bound_packet(dst_ip, src_ip) == 1){
        append_ln_to_log_file_nat("NAT: Packet is local bound, not processing.");
        return;
    }    

    struct nat_entry *incoming_packet_details = malloc(sizeof(struct nat_entry));

    incoming_packet_details->orig_ip = src_ip;
    incoming_packet_details->protocol = ip_header->protocol;
    
    struct nat_entry *translated_nat_entry;

    // Extraction of ip and port.
    switch (ip_header->protocol){
        case ICMP_IP_TYPE:
            // There're different types of ICMP packets, I'm considering only echo request, reply and errors.
            // Request and reply has their own identifier to be considered as port.
            // For errors, I'm going to use the original packet headers to find the IP and port. I'm assuming these will be for TCP.
            const struct icmp_header *icmp_h = extract_icmp_header_from_ipv4_packet(ip_packet);
            
            if (icmp_h->type == 0){
                const struct icmp_echo *icmp_echo_packet = extract_icmp_echo_header_from_ipv4_packet(ip_packet);
                incoming_packet_details->orig_port = ntohs(icmp_echo_packet->identifier);  // ICMP query ID as "port"
            }
            else if (icmp_h->type == 3 || icmp_h->type == 11 || icmp_h->type == 12) {
                const struct icmp_error *icmp_error_packet = extract_icmp_error_header_from_ipv4_packet(ip_packet);
                struct ipv4_header *orig_ip_hdr = (struct ipv4_header*)icmp_error_packet->orig_header;  
                if (orig_ip_hdr->protocol == IPPROTO_TCP) {  
                    // If TCP, update the packet details with original for the search->
                    struct tcp_header *orig_tcp_hdr = (struct tcp_header*)(orig_ip_hdr + 1);
                    incoming_packet_details->orig_ip = orig_ip_hdr->saddr;
                    incoming_packet_details->orig_port = ntohs(orig_tcp_hdr->sport);
                    incoming_packet_details->protocol = IPPROTO_TCP;
                }
            }
            break;


        case TCP_IP_TYPE:

            append_ln_to_log_file_nat("NAT: Outbound TCP packet.");
            const struct tcp_header *tcp_h = extract_tcp_header_from_ipv4_packet(ip_packet);
            
            incoming_packet_details->orig_port = ntohs(tcp_h->sport);
            dport = ntohs(tcp_h->dport);
            
            translated_nat_entry = enrich_entry(incoming_packet_details);
            if (translated_nat_entry == NULL) {
                append_ln_to_log_file_nat("[Error] Failed to enrich entry.");
                return;
            }

            size_t tcp_header_len = tcp_h->doff * 4;
            uint8_t *tcp_payload = ip_packet->payload + tcp_header_len;
            size_t tcp_payload_len = ntohs(ip_header->tot_len) - (ip_header->ihl * 4) - tcp_header_len;
            
            // Translation:
            ip_header->saddr = translated_nat_entry->trans_ip;

            // Network byte order translation happens in update_tcp_ports.
            // Manually assign the translation and call the checksum. Don't use the function.
    

            break;


        case UDP_IP_TYPE:{
            // Extraction
            struct udp_header *udp_h = extract_udp_header_from_ipv4_packet(ip_packet);
            append_ln_to_log_file_nat("NAT: Outbound UDP packet.");
            uint16_t udp_len_host = ntohs(udp_h->len);
            append_ln_to_log_file_nat("NAT: Outbound UDP packet.");
        
            size_t udp_payload_len = (udp_len_host > sizeof(struct udp_header)) 
                               ? (udp_len_host - sizeof(struct udp_header)) 
                               : 0;

            // CORRECTED: Remove & from ip_packet->payload
            const uint8_t *udp_payload = (const uint8_t *)(udp_h + 1); // Point to payload after UDP header

            uint16_t received_check = ntohs(udp_h->check);
            udp_h->check = 0;
            // CORRECTED: Remove & from ip_header and udp_h
            uint16_t udp_check = compute_udp_checksum(ip_header, udp_h, udp_payload, udp_payload_len);
        
            // Handle zero checksum special case (RFC 768)
            if (udp_check == 0) udp_check = 0xFFFF;
        
            append_ln_to_log_file_nat("UDP checksum before any change: 0x%04" PRIx16 ", received checksum value: 0x%04" PRIx16, 
                                ntohs(udp_check), received_check);

            // Translation:
            translated_nat_entry = enrich_entry(incoming_packet_details);
            if (translated_nat_entry == NULL) {
                append_ln_to_log_file_nat("[Error] Failed to enrich entry.");
                return;
            }

            ip_header->saddr = translated_nat_entry->trans_ip;
            
            udp_h->sport = htons(translated_nat_entry->trans_port);
        
            // Recompute checksum with new ports and IP
            udp_h->check = 0;
            udp_check = compute_udp_checksum(ip_header, udp_h, udp_payload, udp_payload_len);
            if (udp_check == 0) udp_check = 0xFFFF;  // Handle zero case
        
            udp_h->check = udp_check;
            break;
        }
        default:
            // Unsupported protocol - don't process.            
            return;
    }

    append_ln_to_log_file_nat("Outbound Packet details:");

    unsigned char *bytes = (unsigned char *)&ip_header->saddr;
    append_ln_to_log_file_nat("LAN IP: %d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

    append_ln_to_log_file_nat("LAN Port: %u", incoming_packet_details->trans_port);
    bytes = (unsigned char *)&dst_ip;
    append_ln_to_log_file_nat("WAN IP: %d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    append_ln_to_log_file_nat("WAN Port: %u", dport);
    append_ln_to_log_file_nat("Protocol: %u", incoming_packet_details->protocol);

    
    // Recalculate IP checksum
    ip_header->check = 0; // Reset checksum before recalculation
    ip_header->check = compute_checksum(ip_header, ip_header->ihl * 4);
    append_ln_to_log_file_nat("NAT: Updated IP checksum: %u", ip_header->check);


    // Update Ethernet headers for WAN interface
    uint8_t wan_mac_1[6] = {0x08, 0x00, 0x27, 0x03, 0x44, 0xa4}; // 10.0.2.15
    memcpy(eth_header->src_mac, wan_machine_mac, 6);
    
    // uint8_t dst_mac[6] = {0x52, 0x55, 0x0a, 0x00, 0x02, 0x02}; // 10.0.2.2

    // Check ARP cache for gateway MAC
    struct arp_cache_entry *entry;
    HASH_FIND_INT(arp_cache, &wan_gateway_ip, entry);
    
    if (entry) {
        // MAC known - send immediately
        memcpy(eth_header->dst_mac, entry->mac, 6);
        send_raw_frame(entry->mac, ETH_P_IP, eth_frame, len, OUTBOUND);
        append_ln_to_log_file_nat("NAT: Sent packet to known MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                                entry->mac[0], entry->mac[1], entry->mac[2],
                                entry->mac[3], entry->mac[4], entry->mac[5]);
    } else {
        // Buffer translated packet and request MAC
        buffer_packet(eth_frame, len, wan_gateway_ip, OUTBOUND);
        send_arp_request(wan_gateway_ip, OUTBOUND);
        append_ln_to_log_file_nat("NAT: Buffered packet awaiting ARP resolution");
    }

    append_ln_to_log_file_nat(NULL);

    // https://www.rfc-editor.org/rfc/rfc4787#section-4.3 for timeouts.
    // For UDP, only update for an outbound packet.
    // ICMP inbound packets are either failed IP connection, or a ping test, just map it and update the timeout to 60 sec.
    // For ICMP outbound packets, update the NAT table.
    
}


void handle_inbound_packet(unsigned char *buffer, ssize_t len) {
    append_ln_to_log_file_nat("NAT: Inbound frame of size %d.", len);
    // Get ethernet frame and header.
    struct raw_ethernet_frame *eth_frame = extract_ethernet_frame(buffer);
    struct ethernet_header *eth_header = &eth_frame->header;

    append_ln_to_log_file_nat("NAT: Ethernet header type: %u", ntohs(eth_header->type));

    if (is_packet_outgoing(eth_header))
    {
        append_ln_to_log_file_nat_verbose("[Verbose] [info] Outbound packet, not processing.");
        return;
    }

    uint16_t eth_type_host = ntohs(eth_header->type);
    if (eth_type_host == ARP_ETH_TYPE){
        handle_arp_reply(buffer, len);
    }
    else if (eth_type_host != IPV4_ETH_TYPE){
        return;
    }    
    
    // Get IP packet and header.
    struct ipv4_packet *ip_packet = extract_ipv4_packet_from_eth_payload(&eth_frame->payload);
    struct ipv4_header *ip_header = extract_ipv4_header_from_ipv4_packet(ip_packet);

    if(ip_header->version != 4) return;                   // Anything other than IPv4 SHALL NOT PASS!

    // Copy src address and dsr address.
    uint16_t sport, dport;
    uint32_t src_ip = ip_header->saddr;
    uint32_t dst_ip = ip_header->daddr;
    append_ln_to_log_file_nat("NAT: Inbound ipv4 packet.");

    struct nat_entry packet_details;

    switch (ip_header->protocol){
        case ICMP_IP_TYPE:
            // NOTE TO SELF: Implemented below by mistake, leaving it here for future use. This was meant to be for outbound.
            // There're different types of ICMP packets, I'm considering only echo request, reply and errors.
            // Request and reply has their own identifier to be considered as port.
            // For errors, I'm going to use the original packet headers to find the IP and port. I'm assuming these will be for TCP.
            const struct icmp_header *icmp_h = extract_icmp_header_from_ipv4_packet(ip_packet);
            if (icmp_h->type == 0){
                const struct icmp_echo *icmp_echo_packet = extract_icmp_echo_header_from_ipv4_packet(ip_packet);
                sport = ntohs(icmp_echo_packet->identifier);  // ICMP query ID as "port"
            }
            else if (icmp_h->type == 3 || icmp_h->type == 11 || icmp_h->type == 12) {
                const struct icmp_error *icmp_error_packet = extract_icmp_error_header_from_ipv4_packet(ip_packet);
                struct ipv4_header *orig_ip_hdr = (struct ipv4_header*)icmp_error_packet->orig_header;  
                if (orig_ip_hdr->protocol == IPPROTO_TCP) {  
                    struct tcp_header *orig_tcp_hdr = (struct tcp_header*)(orig_ip_hdr + 1);

                    sport = ntohs(orig_tcp_hdr->sport);
                    // struct nat_entry *e = find_by_original(orig_ip_hdr->saddr, orig_tcp_hdr->sport, IPPROTO_TCP);  
                }
            }
            break;
        case TCP_IP_TYPE:
            const struct tcp_header *tcp_h = extract_tcp_header_from_ipv4_packet(ip_packet);
            
            sport = ntohs(tcp_h->sport);
            dport = ntohs(tcp_h->dport);

            // Handle TCP connection state.
            break;
        case UDP_IP_TYPE:
            const struct udp_header *udp_h = extract_udp_header_from_ipv4_packet(ip_packet);
            sport = ntohs(udp_h->sport);
            dport = ntohs(udp_h->dport);
            // Handle this UDP packet and reset the timeout.
            break;
        default:
            // Unsupported protocol
            
            return;
    }
    packet_details.orig_ip = src_ip;
    packet_details.orig_port = sport;
}

void nat_main(int router_rx, int router_tx, int verbose_l, char * parent_dir) {

    if (chdir(parent_dir) < 0) {
        append_ln_to_log_file_nat("Error changing directory to  %s\n", parent_dir);
    } else {
        char cwd[256];
        getcwd(cwd, 256);
        append_ln_to_log_file_nat("Changed working directory to %s\n", cwd);
    }
    

    rx_fd = router_rx;
    tx_fd = router_tx;
    verbose = verbose_l;
    
    unsigned char buffer[BUFFER_SIZE];
    char command_from_router[256];

    // Send the PID to router process for "killing" purposes.
    pid_t pid = getpid();
    send_to_router(&pid, sizeof(pid_t));
    
    append_ln_to_log_file_nat("NAT service started.");

    init_and_load_configurations();

    time_t last_cleanup = time(NULL);   // Started empty.


    fd_set read_fds;
    while(1) {
        FD_ZERO(&read_fds);
        FD_SET(lan_raw, &read_fds);
        FD_SET(wan_raw, &read_fds);
        FD_SET(rx_fd, &read_fds);
        
        // Calculate time until next cleanup  
        time_t now = time(NULL);  
        time_t next_cleanup = last_cleanup + cleanup_interval;  
        int sec_remaining = (next_cleanup > now) ? (next_cleanup - now) : 0;

        // Check if cleanup is due  
        if (sec_remaining >= cleanup_interval) {  
            nat_table_cleanup();  
            last_cleanup = now;  
        }
        // TODO: Hasn't cleaned the entries even after the timeout. Check the time from 6:45 to 5:50 22nd April.


        struct timeval tv = {.tv_sec = 1, .tv_usec = 0}; // 1 second select timeout.
        int ready = select(FD_SETSIZE, &read_fds, NULL, NULL, &tv);
        
        if(ready < 0) {
            append_ln_to_log_file_nat("[Critical] fd set: 'Select' error");
            break;
        }

        if (FD_ISSET(rx_fd, &read_fds)) {
            memset(command_from_router, 0, sizeof(command_from_router));
            int count = read(rx_fd, command_from_router, sizeof(command_from_router) - 1);
            
            // Process router command
            if (count <= 0 || strcmp(command_from_router, "shutdown") == 0) {
                append_ln_to_log_file_nat("Received shutdown command from router: Shutting down.");
                send_to_router("NAT: Shutting down.", 13);
                break;
            } 
            else if (strcmp(command_from_router, "clear logs") == 0) {
                clear_log_file();
                append_ln_to_log_file_nat("[Router Command] clear logs");
                append_ln_to_log_file_nat(NULL);
                write(tx_fd, "Cleared logs.\n", count);
            }
            else {
                char msg[300];
                snprintf(msg, sizeof(msg), "NAT: Unknown command '%s'\n", command_from_router);
                write(tx_fd, msg, strlen(msg));
            }
        }

        if(FD_ISSET(lan_raw, &read_fds)) {
            ssize_t len = recv(lan_raw, buffer, BUFFER_SIZE, 0);
            if(len > 0) handle_outbound_packet(buffer, len);
        }

        if(FD_ISSET(wan_raw, &read_fds)) {
            ssize_t len = recv(wan_raw, buffer, BUFFER_SIZE, 0);
            if(len > 0) handle_inbound_packet(buffer, len);
        }
    }

    close(lan_raw);
    close(wan_raw);
    close(rx_fd);
    close(tx_fd);
    exit(EXIT_SUCCESS);
}
