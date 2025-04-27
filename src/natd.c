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

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <time.h>
#include "packet_helper.h"


#define BUFFER_SIZE 1518                // To cover the whole ethernet frame.
#define START_PORT 60000
#define DEFAULT_LAN_IFACE "enp0s8"      // Configurable by command.
#define DEFAULT_WAN_IFACE "enp0s3"      // Configurable by command.
#define MAX_LOG_SIZE 5 * 1024 * 1024    // 5MB default
#define DEFAULT_LOG_PATH "/home/osboxes/cs536/router/logs/nat_log.txt"

#define TCP_IP_TYPE 6
#define UDP_IP_TYPE 17
#define ICMP_IP_TYPE 1
#define IPV4_ETH_TYPE 2048              // 0x0800 in decimal.
#define NAT_TABLE_SIZE 4096             // Power of 2 for bitmask optimization  
#define MASK 0xFFFFFF00
#define TCP_TIMEOUT_DEFAULT 4 * 60 * 60 // 4 hrs in seconds.
#define UDP_TIMEOUT_DEFAULT 5 * 60      // 5 min in seconds.
#define ICMP_TIMEOUT_DEFAULT 60         // 1 min.
#define CLEANUP_INTERVAL_DEFAULT 5 * 60         // 5 min in seconds.

// Reserved ports (Don't use these for assigning outbound ports to WAN.)
// 22 to ssh into the linux machine.
// 53 to use DNS.
// 80 and 8080 for http
// 443 for https.
// If there is something on these ports, pass through if it exists in the 

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



// NAT configuration file format:
typedef struct {
    uint32_t public_ip;         // External IP (network byte order)
    uint16_t port_start;        // 60000
    uint16_t port_end;          // 65000
    uint8_t tcp_timeout;        // In minutes (default 60)
    uint8_t udp_timeout;        // In minutes (default 5)
    uint8_t icmp_timeout;       // In seconds (default 60)
    char log_path[256];         // "/var/log/natd.log"
    size_t max_log_size;        // 10MB default
} nat_global_config;

typedef struct {
    uint32_t private_ip;        // Internal IP (0 for wildcard)
    uint16_t private_port;      // Internal port (0 for wildcard)
    uint32_t public_ip;         // Mapped public IP
    uint16_t public_port;       // Mapped public port
    uint8_t protocol;           // 6=TCP, 17=UDP, 1=ICMP
} nat_static_mapping;

typedef struct {
    char iface_name[IFNAMSIZ];  // Load the default "enp0s8", if not found in the config file.
    uint8_t is_in_local_area;          // 0=WAN, 1=LAN
} nat_interface;

// Global variables:
static int lan_raw, wan_raw, rx_fd, tx_fd;
static char *log_file_path = DEFAULT_LOG_PATH;
static uint8_t wan_mac[6];
static uint32_t wan_gateway_ip, lan_gateway_ip_as_int;
static char wan_gateway_ip_str[INET_ADDRSTRLEN];
static char lan_gateway_ip[INET_ADDRSTRLEN];
static int verbose, tcp_timeout = TCP_TIMEOUT_DEFAULT, udp_timeout = UDP_TIMEOUT_DEFAULT, icmp_timeout = ICMP_TIMEOUT_DEFAULT, cleanup_interval = CLEANUP_INTERVAL_DEFAULT;

// Explicit Function Declarations:
int init_socket(char *iface_name);
void append_ln_to_log_file(const char *msg, ...);
void append_ln_to_log_file_verbose(const char *msg, ...);
static void vappend_ln_to_log_file(const char *msg, va_list args);



/// Utility Functions:

int is_local_bound_packet(uint32_t dst_ip, uint32_t src_ip) {
    // Compare against LAN subnet mask (e.g., 192.168.20.0/24) Comms to gateway machine.
    // TODO: Drop packets LAN 192.168.20.1 - This works now.
    uint32_t src_ip_host = ntohl(src_ip);
    uint32_t dst_ip_host = ntohl(dst_ip);
    int is_local = (dst_ip_host & MASK) == (src_ip_host & MASK);
    // append_ln_to_log_file("NAT: dst_ip & 0xFFFFFF00: %d", (dst_ip_host & 0xFFFFFF00));
    // append_ln_to_log_file("NAT: src_ip & 0xFFFFFF00: %d", (src_ip_host & 0xFFFFFF00));
    return is_local;
}

// Checks if src MAC address is of the WAN iface.
int is_packet_outgoing(struct ethernet_header *eth_header){
    return memcmp(eth_header->src_mac, wan_mac, 6) == 0;
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
    append_ln_to_log_file("Allocated port: %u", candidate);

    if (next_port > 60999) next_port = 32768; 
    return candidate;  
}  

// Obsolete: I'm planning on using an ARP table to get MAC from IP.
void load_wan_next_hop_mac(const char *iface) {  
    int fd = socket(AF_INET, SOCK_DGRAM, 0);  
    struct ifreq ifr;  

    strncpy(ifr.ifr_name, iface, IFNAMSIZ);  
    ioctl(fd, SIOCGIFHWADDR, &ifr);  
    memcpy(wan_mac, ifr.ifr_hwaddr.sa_data, 6);  

    close(fd);  
}  


// Sends binary content to router.
void send_to_router(unsigned char *msg, int msg_len) {
    write(tx_fd, msg, msg_len);
}

char* time_to_fstr(time_t _time, char buffer[26]){
    strftime(*buffer, 26, "%Y-%m-%d %H:%M:%S", localtime(&_time));
}

static void vappend_ln_to_log_file(const char *msg, va_list args) {

    // Clean up the log file if the size is more than 10 MB.
    va_list argp;  

    FILE *log_file = fopen(log_file_path, "r");
    if (log_file) {
        fseek(log_file, 0, SEEK_END);
        long file_size = ftell(log_file);
        fclose(log_file);
        
        if (file_size > MAX_LOG_SIZE) {
            log_file = fopen(log_file_path, "w");
            if (log_file) {
                fprintf(log_file, "\n\n");
                fclose(log_file);
                append_ln_to_log_file("Log file size exceeded %d bytes. Cleared the log file.", MAX_LOG_SIZE);
            }
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

void append_ln_to_log_file(const char *msg, ...) {
    
    va_list args;
    va_start(args, msg);
    vappend_ln_to_log_file(msg, args);
    va_end(args);
}

void append_ln_to_log_file_verbose(const char *msg, ...) {
    if (verbose != 1) return;

    va_list args;
    va_start(args, msg);
    vappend_ln_to_log_file(msg, args);
    va_end(args);
}

int get_gateway_ip(const char *iface, char *gateway_ip, size_t size) {

    
    int temp_sock;  // Temporary socket for IP lookup
    struct ifreq ifr;

    // Get IP address using a temporary socket
    if((temp_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        append_ln_to_log_file("Temp socket creation failed on iface %s.", iface);
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if(ioctl(temp_sock, SIOCGIFADDR, &ifr) < 0) {
        append_ln_to_log_file("IP address retrieval failed on iface %s. Continuing without it.", iface);
        close(temp_sock);
    }
    
    // Store IP
    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    uint32_t ip_buffer = ip_addr->sin_addr.s_addr;
    
    inet_ntop(AF_INET, &ip_buffer, gateway_ip, INET_ADDRSTRLEN);
    close(temp_sock);

}


// Using the config files above load the configurations into the NAT table.
// This should be called once at the start of the program.
void init_and_load_configurations() {
       
    append_ln_to_log_file_verbose("Verbose mode enabled.");
    
    // Load defaults:

    // Interface and socket setup
    wan_raw = init_socket(DEFAULT_WAN_IFACE);
    lan_raw = init_socket(DEFAULT_LAN_IFACE);
    
    // Obsolete: I'm planning on using an ARP table to get MAC from IP.
    // load_wan_next_hop_mac(DEFAULT_WAN_IFACE);

    get_gateway_ip(DEFAULT_WAN_IFACE, wan_gateway_ip_str, sizeof(wan_gateway_ip_str));
    get_gateway_ip(DEFAULT_LAN_IFACE, lan_gateway_ip, sizeof(lan_gateway_ip));
    
    struct in_addr addr;
    inet_pton(AF_INET, wan_gateway_ip_str, &addr);
    wan_gateway_ip = addr.s_addr;

    append_ln_to_log_file("[info] WAN Gateway IP: %s", wan_gateway_ip_str);
    append_ln_to_log_file("[info] LAN Gateway IP: %s", lan_gateway_ip);
    
    append_ln_to_log_file("[info] WAN and LAN interfaces ready.");

    // If failed, throw a critical error to router and log it.
}


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

    append_ln_to_log_file("Find by: %s:%u", src_ip_str, details->orig_port);
    
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

            append_ln_to_log_file("Found entry: %s:%u", ip_str, b->entry->trans_port);
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
        
        append_ln_to_log_file("NAT: Existing entry found: %s:%u -> %s:%u",
                                inet_ntoa(*(struct in_addr*)&details->orig_ip),
                                details->orig_port,
                                ip_str,
                                existing->trans_port);
        return existing;
    }

    // Create new entry
    struct nat_entry *new_entry = malloc(sizeof(struct nat_entry));
    if (!new_entry) {
        append_ln_to_log_file("NAT: Failed to allocate new entry");
        return NULL;
    }

    *new_entry = (struct nat_entry){
        .orig_ip = details->orig_ip,
        .orig_port = details->orig_port,
        .trans_ip = wan_gateway_ip,
        .trans_port = allocate_port(details->protocol),
        .protocol = details->protocol,
        .last_used = time(NULL)
    };

    // Log creation    
    char src_ip_str[INET_ADDRSTRLEN], wan_ip_str[INET_ADDRSTRLEN];
          
    inet_ntop(AF_INET, &new_entry->orig_ip, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &new_entry->trans_ip, wan_ip_str, INET_ADDRSTRLEN);
    
    append_ln_to_log_file("NAT: Created new entry: %s:%u translates as %s:%u",
                            src_ip_str,
                            new_entry->orig_port,
                            wan_ip_str,
                            new_entry->trans_port);

    // Add to hash table
    uint32_t h = hash_key(details->orig_ip, details->orig_port, details->protocol) % NAT_TABLE_SIZE;
    struct nat_bucket *new_bucket = malloc(sizeof(struct nat_bucket));
    if (!new_bucket) {
        free(new_entry);
        append_ln_to_log_file("NAT: Failed to allocate new bucket");
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
                append_ln_to_log_file("Removing entry which was last used on %d.", curr->entry->last_used);
                free(curr->entry);  
                free(curr);  
            } else {  
                prev = &curr->next;  
            }  
        }  
    }  
}

/// Packet processing:


int init_socket(char *iface_name){
    
    struct sockaddr_ll saddr;
    struct ifreq ifr;
    int raw_sock;

    if((raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        append_ln_to_log_file("NAT: Socket creation failed.");

        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
    if(ioctl(raw_sock, SIOCGIFINDEX, &ifr) < 0) {
        append_ln_to_log_file("NAT: Interface config failed.");
        close(raw_sock);
        exit(EXIT_FAILURE);
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_ifindex = ifr.ifr_ifindex;
    saddr.sll_protocol = htons(ETH_P_ALL);
    
    if(bind(raw_sock, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        append_ln_to_log_file("NAT: Bind failed.");
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



void update_udp_ports_1(struct ipv4_header* ip, struct udp_header* udp, uint16_t new_src, uint16_t new_dst, uint8_t *payload, size_t payload_len) {
    udp->sport = htons(new_src);
    udp->dport = htons(new_dst);
    append_ln_to_log_file("Before calling udp checksum: Updated UDP ports: %u -> %u", new_src, new_dst);
    update_udp_checksum_1(ip, udp, payload, payload_len);
}

void update_udp_checksum_1(struct ipv4_header* ip, struct udp_header* udp, uint8_t *udp_payload, size_t payload_len) {
    udp->check = 0;
    
    // Pseudo-header for checksum calculation
    struct {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zeros;
        uint8_t protocol;
        uint16_t udp_len;
    } pseudo_header;

    pseudo_header.src_addr = ip->saddr;
    pseudo_header.dst_addr = ip->daddr;
    pseudo_header.zeros = 0;
    pseudo_header.protocol = IPPROTO_UDP;
    pseudo_header.udp_len = udp->len;

    append_ln_to_log_file("Before calling udp checksum: UDP length: %u", pseudo_header.udp_len);

    // Calculate checksum over pseudo-header
    uint32_t sum = compute_checksum(&pseudo_header, sizeof(pseudo_header));

    append_ln_to_log_file("Pseudo header checksum: %d", sum);

    // Add the UDP header and payload
    sum += compute_checksum(udp, sizeof(struct udp_header));

    append_ln_to_log_file("After udp headers are added: %d", sum);
    append_ln_to_log_file("Length of udp payload: %d", payload_len);

    sum += compute_checksum(udp_payload, payload_len);

    append_ln_to_log_file("After payload: %d", sum);

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    append_ln_to_log_file("Final checksum: %d", ~sum);

    udp->check = ~sum;
}




// Flow: From LAN to WAN => 192.168.20.2 -> 172.217.215.102
void handle_outbound_packet(unsigned char *buffer, ssize_t len) {
    
    // Get ethernet frame and header.
    struct raw_ethernet_frame *eth_frame = extract_ethernet_frame(buffer);
    struct ethernet_header *eth_header = &eth_frame->header;

    append_ln_to_log_file("Handle outbound: Ethernet header type: %u", ntohs(eth_header->type));
    
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
        append_ln_to_log_file("NAT: Packet is local bound, not processing.");
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

            append_ln_to_log_file("NAT: Outbound TCP packet.");
            const struct tcp_header *tcp_h = extract_tcp_header_from_ipv4_packet(ip_packet);
            
            incoming_packet_details->orig_port = ntohs(tcp_h->sport);
            dport = ntohs(tcp_h->dport);
            
            translated_nat_entry = enrich_entry(incoming_packet_details);
            if (translated_nat_entry == NULL) {
                append_ln_to_log_file("[Error] Failed to enrich entry.");
                return;
            }

            size_t tcp_header_len = tcp_h->doff * 4;
            uint8_t *tcp_payload = ip_packet->payload + tcp_header_len;
            size_t tcp_payload_len = ntohs(ip_header->tot_len) - (ip_header->ihl * 4) - tcp_header_len;
            
            // Translation:
            ip_header->saddr = translated_nat_entry->trans_ip;

            // Network byte order translation happens in update_tcp_ports.
            update_tcp_ports(ip_header, tcp_h,
                translated_nat_entry->trans_port,  // New source port (WAN)
                dport,                             // Original destination port
                tcp_payload, tcp_payload_len
            );      // This updated TCP checksum as well.
    

            break;


        case UDP_IP_TYPE:{
            struct udp_header *udp_h = extract_udp_header_from_ipv4_packet(ip_packet);
            incoming_packet_details->orig_port = ntohs(udp_h->sport);
            dport = ntohs(udp_h->dport);

            
            char src_ip_str[INET_ADDRSTRLEN];
            char dst_ip_str[INET_ADDRSTRLEN];
          
            inet_ntop(AF_INET, &incoming_packet_details->orig_ip, src_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip_header->daddr, dst_ip_str, INET_ADDRSTRLEN);

            append_ln_to_log_file("Before processing: %s:%u -> %s:%u", src_ip_str, incoming_packet_details->orig_port, dst_ip_str, dport);

            translated_nat_entry = enrich_entry(incoming_packet_details);
            if (translated_nat_entry == NULL) {
                append_ln_to_log_file("[Error] Failed to enrich entry.");
                return;
            }
            // Translation:
            ip_header->saddr = translated_nat_entry->trans_ip;
            
            uint16_t udp_len_host = ntohs(udp_h->len);
            // Calculate payload length (ensure non-negative)
            size_t payload_len = (udp_len_host > sizeof(struct udp_header)) 
                               ? (udp_len_host - sizeof(struct udp_header)) 
                               : 0;

            uint8_t udp_payload[payload_len];
            memcpy(udp_payload, &ip_packet->payload + sizeof(struct udp_header), payload_len); // Copy UDP payload
            
            update_udp_ports_1(ip_header, udp_h, translated_nat_entry->trans_port, dport, udp_payload, ntohs(udp_h->len) - sizeof(struct udp_header));

            break;
        }
        default:
            // Unsupported protocol - don't process.            
            return;
    }

    append_ln_to_log_file("Outbound Packet details:");

    unsigned char *bytes = (unsigned char *)&ip_header->saddr;
    append_ln_to_log_file("LAN IP: %d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

    append_ln_to_log_file("LAN Port: %u", incoming_packet_details->trans_port);
    bytes = (unsigned char *)&dst_ip;
    append_ln_to_log_file("WAN IP: %d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    append_ln_to_log_file("WAN Port: %u", dport);
    append_ln_to_log_file("Protocol: %u", incoming_packet_details->protocol);
    append_ln_to_log_file(NULL);

    
    // Recalculate IP checksum
    update_ip_checksum(&ip_header);
    append_ln_to_log_file("NAT: Updated IP checksum: %u", ip_header->check);


    // Update Ethernet headers for WAN interface
    uint8_t wan_mac_1[6] = {0x08, 0x00, 0x27, 0x03, 0x44, 0xa4}; // 10.0.2.15
    memcpy(eth_header->src_mac, wan_mac_1, 6);
    
    uint8_t dst_mac[6] = {0x52, 0x55, 0x0a, 0x00, 0x02, 0x02}; // 10.0.2.2
    memcpy(eth_header->dst_mac, dst_mac, 6); // Set destination MAC to WAN MAC

    struct sockaddr_ll dest_addr = {
    .sll_family = AF_PACKET,
    .sll_protocol = htons(ETH_P_ALL),
    .sll_ifindex = if_nametoindex("enp0s3"),  // Replace with WAN interface
    .sll_halen = ETH_ALEN,
    .sll_addr = {0x52, 0x55, 0x0a, 0x00, 0x02, 0x02} // Broadcast MAC
    // 08 00 27 03 44 a4  // 10.0.2.15
};
    // Send the packet to the WAN interface.
    ssize_t sent_bytes = sendto(wan_raw, buffer, len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    if (sent_bytes < 0) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), 
            "NAT: Send failed: %s (errno=%d)", 
            strerror(errno), errno);
        append_ln_to_log_file(err_msg);
    }
    append_ln_to_log_file("NAT: Sent %zd bytes to WAN interface.", sent_bytes);
    append_ln_to_log_file("NAT: Outbound packet sent to WAN interface.");

    // https://www.rfc-editor.org/rfc/rfc4787#section-4.3 for timeouts.
    // For UDP, only update for an outbound packet.
    // ICMP inbound packets are either failed IP connection, or a ping test, just map it and update the timeout to 60 sec.
    // For ICMP outbound packets, update the NAT table.
    
}


void handle_inbound_packet(unsigned char *buffer, ssize_t len) {
    append_ln_to_log_file("NAT: Inbound frame of size %d.", len);
    // Get ethernet frame and header.
    struct raw_ethernet_frame *eth_frame = extract_ethernet_frame(buffer);
    struct ethernet_header *eth_header = &eth_frame->header;

    append_ln_to_log_file("NAT: Ethernet header type: %u", ntohs(eth_header->type));

    if (is_packet_outgoing(eth_header))
    {
        append_ln_to_log_file_verbose("[Verbose] [info] Outbound packet, not processing.");
        return;
    }
    
    if(ntohs(eth_header->type) != IPV4_ETH_TYPE) return;  // Anything other than IPv4 SHALL NOT PASS!
    
    // Get IP packet and header.
    struct ipv4_packet *ip_packet = extract_ipv4_packet_from_eth_payload(&eth_frame->payload);
    struct ipv4_header *ip_header = extract_ipv4_header_from_ipv4_packet(ip_packet);

    if(ip_header->version != 4) return;                   // Anything other than IPv4 SHALL NOT PASS!

    // Copy src address and dsr address.
    uint16_t sport, dport;
    uint32_t src_ip = ip_header->saddr;
    uint32_t dst_ip = ip_header->daddr;
    append_ln_to_log_file("NAT: Inbound ipv4 packet.");

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

void nat_main(int router_rx, int router_tx, int verbose_l) {
    rx_fd = router_rx;
    tx_fd = router_tx;
    verbose = verbose_l;
    
    unsigned char buffer[BUFFER_SIZE];

    // Send the PID to router process for "killing" purposes.
    pid_t pid = getpid();
    send_to_router(&pid, sizeof(pid_t));
    
    append_ln_to_log_file("NAT service started.");

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
            append_ln_to_log_file("[Critical] fd set: 'Select' error");
            break;
        }

        if(FD_ISSET(rx_fd, &read_fds)) {
            char cmd[256];
            // TODO: Update this to handle different configurations.
            if(read(rx_fd, cmd, sizeof(cmd)) <= 0 || strcmp(cmd, "shutdown") == 0) {
                append_ln_to_log_file("Received shutdown command from router: Shutting down.");
                break;
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
