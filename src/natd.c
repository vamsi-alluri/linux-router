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

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <time.h>
#include "packet_helper.h"


#define BUFFER_SIZE 1518            // To cover the whole ethernet frame.
#define START_PORT 60000
#define DEFAULT_LAN_IFACE "enp0s8"  // This has to be configurable.
#define DEFAULT_WAN_IFACE "enp0s3"  // This has to be configurable.
#define CLEANUP_INTERVAL 120        // Once every 5 min.
#define MAX_LOG_SIZE 5 * 1024 * 1024 // 5MB default
#define DEFAULT_LOG_PATH "/home/osboxes/cs536/router/logs/nat_log.txt"

#define TCP_IP_TYPE 6
#define UDP_IP_TYPE 17
#define ICMP_IP_TYPE 1
#define IPV4_ETH_TYPE 2048      // 0x0800 in decimal.
#define NAT_TABLE_SIZE 4096     // Power of 2 for bitmask optimization  
#define MASK 0xFFFFFF00

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
static int verbose;


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

    if (next_port > 60999) next_port = 32768; 
    return candidate;  
}  

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

void append_ln_to_log_file_verbose(const char *msg, ...) {
    if (verbose != 1) return;

    va_list args;
    va_start(args, msg);
    vappend_ln_to_log_file(msg, args);
    va_end(args);
}

void append_ln_to_log_file(const char *msg, ...) {
    
    va_list args;
    va_start(args, msg);
    vappend_ln_to_log_file(msg, args);
    va_end(args);
}

// Using the config files above load the configurations into the NAT table.
// This should be called once at the start of the program.
void init_and_load_configurations() {
    // Load NAT configurations from files.
    // This function should read the configuration files and populate the NAT table.
    append_ln_to_log_file("NAT: Loading configurations...");
    
    append_ln_to_log_file_verbose("Verbose mode enabled.");
    
    // TODO: Load public ip.
    // global_conf.public_ip

    // If failed to load from the configuration file, load defaults.
    // Interface and socket setup
    wan_raw = init_socket(DEFAULT_WAN_IFACE);
    lan_raw = init_socket(DEFAULT_LAN_IFACE);
    load_wan_next_hop_mac(DEFAULT_WAN_IFACE);

    
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

struct nat_entry *find_by_original(uint32_t orig_ip, uint16_t orig_port, uint8_t proto) {
    uint32_t h = hash_key(orig_ip, orig_port, proto) % NAT_TABLE_SIZE;
    for (nat_bucket *b = nat_table[h]; b != NULL; b = b->next) {
        if (b->entry->orig_ip == orig_ip && b->entry->orig_port == orig_port && b->entry->protocol == proto) {
                return b->entry;
        }
    }
    return NULL;
}

struct nat_entry *find_by_translated(uint32_t trans_ip, uint16_t trans_port, uint8_t proto) {  
    uint32_t h = hash_key(trans_ip, trans_port, proto) % NAT_TABLE_SIZE;  
    for (nat_bucket *b = nat_table[h]; b != NULL; b = b->next) {  
        if (b->entry->trans_ip == trans_ip &&  
            b->entry->trans_port == trans_port &&  
            b->entry->protocol == proto) {  
            b->entry->last_used = time(NULL);  
            return b->entry;  
        }  
    }  
    return NULL;  // No mapping → drop packet 
}

uint16_t create_entry(uint32_t lan_ip, uint16_t lan_port, uint8_t proto) {  
    uint16_t translated_wan_port;
    struct nat_entry *nat_entry_found = find_by_original(lan_ip, lan_port, proto);
    if (nat_entry_found != NULL)
    {
        // Update 'last_used' and move_on.
        // Get the wan port used previously.
        translated_wan_port = nat_entry_found->trans_port;
        nat_entry_found->last_used = time(NULL);
        struct tm *tm_info = localtime(&nat_entry_found->last_used);
        char buffer[26];
        strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
        append_ln_to_log_file("NAT: Entry found, using the same port and last used is updated to %s", buffer);
    }
    else{
        translated_wan_port = allocate_port(proto); 
        struct nat_entry *e = malloc(sizeof(struct nat_entry));  
        e->orig_ip = lan_ip;  
        e->orig_port = lan_port;  
        // e->trans_ip = wan_ip;  // Router's public IP  TODO: Uncomment this and fix the config load.
        e->trans_port = translated_wan_port;  // Random port 1024-65535  
        e->protocol = proto;  
        e->last_used = time(NULL);  

        uint32_t h = hash_key(lan_ip, lan_port, proto) % NAT_TABLE_SIZE;  
        nat_bucket *b = malloc(sizeof(nat_bucket));  
        b->entry = e;  
        b->next = nat_table[h];  
        nat_table[h] = b;
        append_ln_to_log_file("NAT: Added to table.");
    }

    append_ln_to_log_file("Translated wan port: %d", translated_wan_port);
    return translated_wan_port;
}

// NAT table cleanup.
void nat_table_cleanup() {  
    time_t now = time(NULL);  
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {  
        struct nat_bucket **prev = &nat_table[i];  
        while (*prev != NULL) {  
            struct nat_bucket *curr = *prev;  
            // TODO: should consider different timeout values based on the protocol.
            if (now - curr->entry->last_used > CLEANUP_INTERVAL && now - curr->entry->last_used > curr->entry->custom_timeout) {  // Portforwards could have INT_MAX in custom_timeout.
                *prev = curr->next;  
                append_ln_to_log_file("Removing entry which was last used on %d and Timeout is set to %d sec.", curr->entry->last_used, CLEANUP_INTERVAL);
                free(curr->entry);  
                free(curr);  
            } else {  
                prev = &curr->next;  
            }  
        }  
    }  
}

/// Packet processing:

void handle_outbound_packet(unsigned char *buffer, ssize_t len) {
    
    // Get ethernet frame and header.
    struct raw_ethernet_frame *eth_frame = extract_ethernet_frame(buffer);
    struct ethernet_header *eth_header = &eth_frame->header;

    append_ln_to_log_file("NAT: Ethernet header type: %u", ntohs(eth_header->type));
    
    if(ntohs(eth_header->type) != IPV4_ETH_TYPE) return;  // Anything other than IPv4 SHALL NOT PASS!
    
    // Get IP packet and header.
    struct ipv4_packet *ip_packet = extract_ipv4_packet_from_eth_payload(&eth_frame->payload);
    struct ipv4_header *ip_header = &ip_packet->header;

    if(ip_header->version != 4) return;                   // Anything other than IPv4 SHALL NOT PASS!
    
    // Copy src address and dsr address.
    uint16_t sport, dport;
    uint32_t src_ip = ip_header->saddr;
    uint32_t dst_ip = ip_header->daddr;

    // Is destination IP in the same subnet? Don't process it.
    if (is_local_bound_packet(dst_ip, src_ip) == 1){
        append_ln_to_log_file("NAT: Packet is local bound, not processing.");
        return;
    }

    struct nat_entry packet_details;

    packet_details.orig_ip = src_ip;
    packet_details.protocol = ip_header->protocol;

    append_ln_to_log_file("NAT: IP sub-protocol: %u", ip_header->protocol);

    // Extraction of ip and port.
    switch (ip_header->protocol){
        case ICMP_IP_TYPE:
            // There're different types of ICMP packets, I'm considering only echo request, reply and errors.
            // Request and reply has their own identifier to be considered as port.
            // For errors, I'm going to use the original packet headers to find the IP and port. I'm assuming these will be for TCP.
            const struct icmp_header *icmp_h = extract_icmp_header_from_ipv4_packet(ip_packet);
            
            if (icmp_h->type == 0){
                const struct icmp_echo *icmp_echo_packet = extract_icmp_echo_header_from_ipv4_packet(ip_packet);
                packet_details.orig_port = ntohs(icmp_echo_packet->identifier);  // ICMP query ID as "port"
            }
            else if (icmp_h->type == 3 || icmp_h->type == 11 || icmp_h->type == 12) {
                const struct icmp_error *icmp_error_packet = extract_icmp_error_header_from_ipv4_packet(ip_packet);
                struct ipv4_header *orig_ip_hdr = (struct ipv4_header*)icmp_error_packet->orig_header;  
                if (orig_ip_hdr->protocol == IPPROTO_TCP) {  
                    // If TCP, update the packet details with original for the search.
                    struct tcp_header *orig_tcp_hdr = (struct tcp_header*)(orig_ip_hdr + 1);
                    packet_details.orig_ip = orig_ip_hdr->saddr;
                    packet_details.orig_port = ntohs(orig_tcp_hdr->sport);
                    packet_details.protocol = IPPROTO_TCP;
                }
            }
            break;
        case TCP_IP_TYPE:
            const struct tcp_header *tcp_h = extract_tcp_header_from_ipv4_packet(ip_packet);
            
            packet_details.orig_port = ntohs(tcp_h->sport);
            dport = ntohs(tcp_h->dport);

            // Handle TCP connection state.
            break;
        case UDP_IP_TYPE:
            const struct udp_header *udp_h = extract_udp_header_from_ipv4_packet(ip_packet);
            packet_details.orig_port = ntohs(udp_h->sport);
            dport = ntohs(udp_h->dport);
            // Handle this UDP packet and reset the timeout.


            break;
        default:
            // Unsupported protocol - don't process.            
            return;
    }

    // https://www.rfc-editor.org/rfc/rfc4787#section-4.3
    // Update NAT table with the current data, if not already present. 
    // For UDP, only update for an outbound packet.
    // For TCP, update for both inbound and outbound packets.
    // ICMP inbound packets are either failed IP connection, or a ping test, just map it and update the timeout to 60 sec.
    // For ICMP outbound packets, update the NAT table.
    
    append_ln_to_log_file("Outbound Packet details:");
    
    unsigned char *bytes = (unsigned char *)&packet_details.orig_ip;
    append_ln_to_log_file("LAN IP: %d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    
    append_ln_to_log_file("LAN Port: %u", packet_details.orig_port);
    bytes = (unsigned char *)&dst_ip;
    append_ln_to_log_file("WAN IP: %d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    append_ln_to_log_file("WAN Port: %u", dport);
    append_ln_to_log_file("Protocol: %u", packet_details.protocol);
    append_ln_to_log_file(NULL);
    
    // packet_details.orig_port = sport;
    uint16_t trans_wan_port = create_entry(packet_details.orig_ip, packet_details.orig_port, packet_details.protocol);
    
    // Reassembly
    
    switch (ip_header->protocol){
        case ICMP_IP_TYPE:
            const struct icmp_header *icmp_h = extract_icmp_header_from_ipv4_packet(ip_packet);

            if (icmp_h->type == 0){
                const struct icmp_echo *icmp_echo_packet = extract_icmp_echo_header_from_ipv4_packet(ip_packet);
                sport = ntohs(icmp_echo_packet->identifier);  // ICMP query ID as "port"
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
            // Unsupported protocol - don't process.            
            return;
    }
}


void handle_inbound_packet(unsigned char *buffer, ssize_t len) {
    append_ln_to_log_file("NAT: Inbound frame of size %d.", len);
    // Get ethernet frame and header.
    struct raw_ethernet_frame *eth_frame = extract_ethernet_frame(buffer);
    struct ethernet_header *eth_header = &eth_frame->header;

    append_ln_to_log_file("NAT: Ethernet header type: %u", ntohs(eth_header->type));

    if (is_packet_outgoing(eth_header))
    {
        append_ln_to_log_file_verbose("[info] NAT: Outbound packet, not processing.");
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
                    struct nat_entry *e = find_by_original(orig_ip_hdr->saddr, orig_tcp_hdr->sport, IPPROTO_TCP);  
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
        time_t next_cleanup = last_cleanup + CLEANUP_INTERVAL;  
        int sec_remaining = (next_cleanup > now) ? (next_cleanup - now) : 0;

        // Check if cleanup is due  
        now = time(NULL);  
        if (now - last_cleanup >= CLEANUP_INTERVAL) {  
            nat_table_cleanup();  
            last_cleanup = now;  
        }
        // Hasn't cleaned the entries even after the timeout. Check the time from 6:45 to 5:50 22nd April.


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
            // THIS works append_ln_to_log_file("NAT: Received a packet from LAN, size: %d\n", len);
            if(len > 0) handle_outbound_packet(buffer, len);    // Can also be a local bound packet.
        }

        if(FD_ISSET(wan_raw, &read_fds)) {
            ssize_t len = recv(wan_raw, buffer, BUFFER_SIZE, 0);
            // THIS works append_ln_to_log_file("NAT: Received a packet from WAN, size: %d\n", len);
            if(len > 0) handle_inbound_packet(buffer, len);
        }
    }

    close(lan_raw);
    close(wan_raw);
    close(rx_fd);
    close(tx_fd);
    exit(EXIT_SUCCESS);
}
