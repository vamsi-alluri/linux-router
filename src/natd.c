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
#include <stdbool.h>

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


#define BUFFER_SIZE 9018                // To cover an ethernet frame.
#define DEFAULT_LAN_IFACE "enp0s8"      // Configurable by command.
#define DEFAULT_WAN_IFACE "enp0s3"      // Configurable by command.
#define MAX_LOG_SIZE 5 * 1024 * 1024    // 5MB default
#define DEFAULT_LOG_PATH "/tmp/linux-router/logs/nat.log"

#define TCP_IP_TYPE 6
#define UDP_IP_TYPE 17
#define ICMP_IP_TYPE 1
#define IPV4_ETH_TYPE 2048              // 0x0800 in decimal.
#define ARP_ETH_TYPE 2054               // 0x0806 in decimal.
#define NAT_TABLE_SIZE 32768            // Power of 2 for bitmask optimization  
#define MASK 0xFFFFFF00                 // /24
#define TCP_TIMEOUT_DEFAULT 24 * 60 * 60// 24 hrs.
#define UDP_TIMEOUT_DEFAULT 30          // 30 sec.
#define ICMP_TIMEOUT_DEFAULT 10         // 10 sec.
#define CLEANUP_INTERVAL_DEFAULT 5 * 60 // 5 mins.
#define ARPOP_REQUEST 1                 // ARP request
#define ARPOP_REPLY   2                 // ARP reply
#define ARP_CACHE_TIMEOUT 300           // 5 minutes
#define MAX_BUFFERED_PACKETS 64         // Max packets to buffer for ARP resolution

typedef enum { INBOUND, OUTBOUND } packet_direction_t;
typedef enum {
    NAT_TCP_NEW,
    NAT_TCP_SYN_SENT,
    NAT_TCP_SYN_RECEIVED,
    NAT_TCP_ESTABLISHED,
    NAT_TCP_FIN_WAIT_1,    // Sent FIN, waiting for ACK
    NAT_TCP_FIN_WAIT_2,    // Received ACK for FIN, waiting for peer's FIN
    NAT_TCP_CLOSE_WAIT,    // Received FIN first, need to send FIN
    NAT_TCP_CLOSING,       // Both sides sent FIN, waiting for final ACK
    NAT_TCP_LAST_ACK,      // Sent FIN after CLOSE_WAIT, waiting for ACK
    NAT_TCP_TIME_WAIT      // Wait for 2MSL before closing
} tcp_state;

typedef enum {
    SSH = 22,
    DNS = 31534,        // Local DNS only communicates using 31534.
    HTTP = 80,
    HTTP_ALT = 8080,
    HTTPS = 443,
    FTP = 21,
    SMTP = 25,
    DHCP = 67,          // Local DHCP uses 67.
    NTP = 32432,        // Local NTP only communicates using 32432.
} reserved_ports_for_inbound;

const reserved_ports_for_inbound port_list[] = {
    SSH, DNS, HTTP, HTTP_ALT, HTTPS, FTP, SMTP, DHCP, NTP
};


// Global variables:
static int lan_raw, wan_raw, rx_fd, tx_fd;
static char *log_file_path = DEFAULT_LOG_PATH;
static uint8_t wan_machine_mac[6], lan_machine_mac[6];
static uint32_t wan_machine_ip, lan_machine_ip, wan_gateway_ip;
static char wan_machine_ip_str[INET_ADDRSTRLEN];
static char lan_machine_ip_str[INET_ADDRSTRLEN];
static int verbose, tcp_timeout = TCP_TIMEOUT_DEFAULT, udp_timeout = UDP_TIMEOUT_DEFAULT, icmp_timeout = ICMP_TIMEOUT_DEFAULT, cleanup_interval = CLEANUP_INTERVAL_DEFAULT;
static uint8_t BROADCAST_MAC[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
static struct arp_cache_entry *arp_cache = NULL;
static struct arp_pending_packet *pending_packets = NULL;
static int nat_entry_count = 0;

// Explicit Function Declarations:
int init_socket(char *iface_name);
void append_ln_to_log_file_nat(const char *msg, ...);
void append_ln_to_log_file_nat_verbose(const char *msg, ...);
static void vappend_ln_to_log_file_nat(const char *msg, va_list args);
uint16_t allocate_port(uint8_t protocol);
void send_raw_frame(uint8_t *dest_mac, uint16_t protocol, void *data, size_t len, packet_direction_t direction);


// NAT table:
struct nat_entry{
    uint32_t orig_ip;           // LAN IP
    uint16_t orig_port_host;    // LAN port/ICMP ID - in host byte order.
    uint32_t trans_ip;          // Translated IP - NAT gateway IP
    uint16_t trans_port_host;   // Translated port/ICMP ID - in host byte order.
    uint8_t protocol;           // TCP (6), UDP (17), ICMP (1)
    time_t last_used;           // Used for timeout calculations.
    uint16_t custom_timeout;    // Timeout in seconds - For overriding the default timeout - TCP FIN: 60 sec timeout.
    tcp_state state;            // To track TCP connections.
};

struct nat_bucket {
    struct nat_entry *entry;    // Pointer to NAT entry
    struct nat_bucket *next;    // Next bucket in chain
    bool is_primary;            // Indicates if this bucket "owns" the entry
}; 

// Two hash tables for NAT entries - outbound and inbound.
struct nat_bucket *nat_table_outbound[NAT_TABLE_SIZE];
struct nat_bucket *nat_table_inbound[NAT_TABLE_SIZE]; 

/// NAT table functions:
uint32_t hash_key(uint32_t ip, uint16_t port, uint8_t proto) {  
    uint32_t h = ip ^ (port << 16) ^ proto;  
    h = ((h >> 16) ^ h) * 0x45d9f3b;            // Magic number from: https://github.com/h2database/h2database/blob/56c0b70ba19114b2fdab40637348a56bee0b5cc1/h2/src/test/org/h2/test/store/CalculateHashConstant.java#L159C28-L159C37
    h = ((h >> 16) ^ h) * 0x45d9f3b;  
    return (h >> 16) ^ h;  
}  

const char* protocol_to_str(uint8_t proto) {
    switch(proto) {
        case 6: return "TCP";
        case 17: return "UDP";
        case 1: return "ICMP";
        default: return "OTHER";
    }
}

// Initialize NAT tables
void init_nat_tables(void) {
    // Zero out hash tables
    memset(nat_table_outbound, 0, sizeof(nat_table_outbound));
    memset(nat_table_inbound, 0, sizeof(nat_table_inbound));
    nat_entry_count = 0;
    
    // Set WAN IP (would typically come from configuration)
    struct in_addr addr;
    inet_pton(AF_INET, "203.0.113.1", &addr);  // Example public IP
    wan_machine_ip = addr.s_addr;
    
    append_ln_to_log_file_nat("NAT: Tables initialized with size %d", NAT_TABLE_SIZE);
}

struct nat_entry* add_port_forward(uint16_t wan_port, uint32_t dest_ip, 
                                  uint16_t dest_port, uint8_t protocol) {
    // Create new NAT entry
    struct nat_entry *new_entry = malloc(sizeof(struct nat_entry));
    if (!new_entry) {
        append_ln_to_log_file_nat("NAT: Failed to allocate port forward entry");
        return NULL;
    }
    
    // Initialize the entry
    *new_entry = (struct nat_entry){
        .orig_ip = dest_ip,              // Internal destination IP
        .orig_port_host = dest_port,     // Internal destination port
        .trans_ip = wan_machine_ip,      // WAN IP of the router
        .trans_port_host = wan_port,     // External WAN port
        .protocol = protocol,
        .last_used = time(NULL),
        .custom_timeout = 0,             // Use standard timeouts
        .state = NAT_TCP_ESTABLISHED     // For TCP, assume established
    };
    
    // Log the port forward creation
    char dest_ip_str[INET_ADDRSTRLEN], wan_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &new_entry->orig_ip, dest_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &new_entry->trans_ip, wan_ip_str, INET_ADDRSTRLEN);
    append_ln_to_log_file_nat("NAT: Adding port forward: %s:%u -> %s:%u (%s)",
                            wan_ip_str, wan_port,
                            dest_ip_str, dest_port,
                            protocol_to_str(protocol));
    
    // Add to outbound hash table
    uint32_t oh = hash_key(new_entry->orig_ip, new_entry->orig_port_host, 
                         new_entry->protocol) % NAT_TABLE_SIZE;
    struct nat_bucket *outbound_bucket = malloc(sizeof(struct nat_bucket));
    if (!outbound_bucket) {
        append_ln_to_log_file_nat("NAT: Failed to allocate outbound bucket");
        free(new_entry);
        return NULL;
    }
    
    outbound_bucket->entry = new_entry;
    outbound_bucket->next = nat_table_outbound[oh];
    outbound_bucket->is_primary = true;  // This bucket owns the entry
    nat_table_outbound[oh] = outbound_bucket;
    
    // Add to inbound hash table
    uint32_t ih = hash_key(new_entry->trans_ip, new_entry->trans_port_host, 
                         new_entry->protocol) % NAT_TABLE_SIZE;
    struct nat_bucket *inbound_bucket = malloc(sizeof(struct nat_bucket));
    if (!inbound_bucket) {
        append_ln_to_log_file_nat("NAT: Failed to allocate inbound bucket");
        // Roll back the outbound entry
        nat_table_outbound[oh] = outbound_bucket->next;
        free(outbound_bucket);
        free(new_entry);
        return NULL;
    }
    
    inbound_bucket->entry = new_entry;
    inbound_bucket->next = nat_table_inbound[ih];
    inbound_bucket->is_primary = false;  // Secondary reference
    nat_table_inbound[ih] = inbound_bucket;
    
    // Increment the entry count
    nat_entry_count++;
    
    append_ln_to_log_file_nat("NAT: Port forward added successfully (outbound hash: %u, inbound hash: %u)",
                           oh, ih);
    
    return new_entry;
}

void cleanup_all_nat_entries(void) {
    append_ln_to_log_file_nat("NAT: Cleaning up all entries");
    
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {
        struct nat_bucket *bucket = nat_table_outbound[i];
        
        while (bucket) {
            struct nat_bucket *next = bucket->next;
            
            if (bucket->is_primary) {
                free(bucket->entry);
            }
            
            free(bucket);
            bucket = next;
        }
        
        nat_table_outbound[i] = NULL;
    }
    
    // Just free the buckets in inbound table, not the entries
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {
        struct nat_bucket *bucket = nat_table_inbound[i];
        
        while (bucket) {
            struct nat_bucket *next = bucket->next;
            free(bucket);
            bucket = next;
        }
        
        nat_table_inbound[i] = NULL;
    }
    
    nat_entry_count = 0;
    append_ln_to_log_file_nat("NAT: All entries cleaned up");
    write(tx_fd, "Cleared.", 8);
}

void print_nat_table() {
    char buffer[1024];
    int len;
    
    // Print header
    const char *header = "NAT Table Entries\n";
    const char *separator = "------------------------------------------------\n";
    const char *format = "%-15s:%-6s <-> %-15s:%-6s %s \t%s\n";
    
    write(tx_fd, header, strlen(header));
    write(tx_fd, separator, strlen(separator));
    
    // Print entry count
    len = snprintf(buffer, sizeof(buffer), "Total entries: %d\n\n", nat_entry_count);
    write(tx_fd, buffer, len);
    
    // Process outbound table (no need to process inbound as it contains same entries)
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {
        struct nat_bucket *bucket = nat_table_outbound[i];
        
        while (bucket) {
            struct nat_entry *entry = bucket->entry;
            char orig_ip_str[INET_ADDRSTRLEN], trans_ip_str[INET_ADDRSTRLEN];
            char orig_port_str[8], trans_port_str[8], proto_str[8], timeout_str[8];
            
            // Convert IP addresses to strings
            inet_ntop(AF_INET, &entry->orig_ip, orig_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &entry->trans_ip, trans_ip_str, INET_ADDRSTRLEN);
            
            // Convert ports to strings
            int_to_str(entry->orig_port_host, orig_port_str, sizeof(orig_port_str));
            int_to_str(entry->trans_port_host, trans_port_str, sizeof(trans_port_str));
            int_to_str(entry->custom_timeout, timeout_str, sizeof(timeout_str));

            
            // Get protocol string
            switch (entry->protocol) {
                case 6:  strcpy(proto_str, "TCP"); break;
                case 17: strcpy(proto_str, "UDP"); break;
                case 1:  strcpy(proto_str, "ICMP"); break;
                default: strcpy(proto_str, "OTHER"); break;
            }
            
            // Format the entry line
            len = snprintf(buffer, sizeof(buffer), format,
                         orig_ip_str, orig_port_str,
                         trans_ip_str, trans_port_str,
                         proto_str, timeout_str);
            
            // Write to the file descriptor
            write(tx_fd, buffer, len);
            
            bucket = bucket->next;
        }
    }
    
    write(tx_fd, separator, strlen(separator));
}

// Helper function to convert an integer to a string
void int_to_str(uint16_t num, char *str, size_t size) {
    if (size == 0) return;
    
    // Handle zero case
    if (num == 0) {
        str[0] = '0';
        str[1] = '\0';
        return;
    }
    
    // Convert digits in reverse order
    size_t i = 0;
    while (num > 0 && i < size - 1) {
        str[i++] = '0' + (num % 10);
        num /= 10;
    }
    str[i] = '\0';
    
    // Reverse the string
    size_t start = 0;
    size_t end = i - 1;
    while (start < end) {
        char tmp = str[start];
        str[start] = str[end];
        str[end] = tmp;
        start++;
        end--;
    }
}

// Find NAT entry by original IP:port (outbound lookups)
struct nat_entry* find_by_original(struct nat_entry *details) {
    if (!details) return NULL;
    
    // Calculate hash based on original IP/port
    uint32_t h = hash_key(details->orig_ip, details->orig_port_host, details->protocol) % NAT_TABLE_SIZE;
    
    // Debug log
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &details->orig_ip, ip_str, INET_ADDRSTRLEN);
    append_ln_to_log_file_nat_verbose("Searching outbound hash table for: %s:%u (hash: %u)", 
                            ip_str, details->orig_port_host, h);
    
    // Search in the specific hash bucket
    struct nat_bucket *bucket = nat_table_outbound[h];
    while (bucket) {
        if (bucket->entry->orig_ip == details->orig_ip && 
            bucket->entry->orig_port_host == details->orig_port_host &&
            bucket->entry->protocol == details->protocol) {
            
            // Update timestamp
            bucket->entry->last_used = time(NULL);
            return bucket->entry;
        }
        bucket = bucket->next;
    }
    
    return NULL;
}

// Find NAT entry by translated IP:port (inbound lookups)
struct nat_entry* find_by_translated(struct nat_entry *details) {
    if (!details) return NULL;
    
    // Calculate hash based on translated IP/port
    uint32_t h = hash_key(details->trans_ip, details->trans_port_host, details->protocol) % NAT_TABLE_SIZE;
    
    // Debug log
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &details->trans_ip, ip_str, INET_ADDRSTRLEN);
    append_ln_to_log_file_nat_verbose("Searching inbound hash table for: %s:%u (hash: %u)", 
                            ip_str, details->trans_port_host, h);
    
    // Search in the specific hash bucket
    struct nat_bucket *bucket = nat_table_inbound[h];
    while (bucket) {
        if (bucket->entry->trans_ip == details->trans_ip && 
            bucket->entry->trans_port_host == details->trans_port_host &&
            bucket->entry->protocol == details->protocol) {
            
            // Update timestamp
            bucket->entry->last_used = time(NULL);
            return bucket->entry;
        }
        bucket = bucket->next;
    }
    
    return NULL;
}


// Create or find NAT entry for packet translation
struct nat_entry* enrich_entry(struct nat_entry *details, packet_direction_t direction) {
    if (!details) return NULL;

    struct nat_entry *existing = NULL;
    char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];

    if (direction == OUTBOUND) {
        // Try to find existing entry first
        existing = find_by_original(details);

        if (existing) {
            // Found existing outbound translation
            inet_ntop(AF_INET, &existing->orig_ip, src_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &existing->trans_ip, dst_ip_str, INET_ADDRSTRLEN);
            
            append_ln_to_log_file_nat_verbose("NAT: Using existing outbound entry: %s:%u -> %s:%u",
                                    src_ip_str, existing->orig_port_host,
                                    dst_ip_str, existing->trans_port_host);
            return existing;
        }
        
        // Create new outbound entry
        struct nat_entry *new_entry = malloc(sizeof(struct nat_entry));
        if (!new_entry) {
            append_ln_to_log_file_nat_verbose("NAT: Failed to allocate new outbound entry");
            return NULL;
        }
        
        *new_entry = (struct nat_entry){
            .orig_ip = details->orig_ip,
            .orig_port_host = details->orig_port_host,
            .trans_ip = wan_machine_ip,
            .trans_port_host = allocate_port(details->protocol),
            .protocol = details->protocol,
            .last_used = time(NULL),
            .custom_timeout = 0,
            .state = (details->protocol == 6) ? NAT_TCP_SYN_SENT : NAT_TCP_NEW
        };
        
        // Log creation
        inet_ntop(AF_INET, &new_entry->orig_ip, src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &new_entry->trans_ip, dst_ip_str, INET_ADDRSTRLEN);
        
        append_ln_to_log_file_nat_verbose("NAT: Created new outbound entry: %s:%u -> %s:%u",
                                src_ip_str, new_entry->orig_port_host,
                                dst_ip_str, new_entry->trans_port_host);
        
        // Add to outbound hash table
        uint32_t oh = hash_key(new_entry->orig_ip, new_entry->orig_port_host, new_entry->protocol) % NAT_TABLE_SIZE;
        struct nat_bucket *outbound_bucket = malloc(sizeof(struct nat_bucket));
        if (!outbound_bucket) {
            free(new_entry);
            append_ln_to_log_file_nat_verbose("NAT: Failed to allocate outbound bucket");
            return NULL;
        }
        
        outbound_bucket->entry = new_entry;
        outbound_bucket->next = nat_table_outbound[oh];
        outbound_bucket->is_primary = true;  // This is the primary reference
        nat_table_outbound[oh] = outbound_bucket;
        
        // Add to inbound hash table
        uint32_t ih = hash_key(new_entry->trans_ip, new_entry->trans_port_host, new_entry->protocol) % NAT_TABLE_SIZE;
        struct nat_bucket *inbound_bucket = malloc(sizeof(struct nat_bucket));
        if (!inbound_bucket) {
            append_ln_to_log_file_nat_verbose("NAT: Failed to allocate inbound bucket");
            // Continue with just the outbound entry
        } else {
            inbound_bucket->entry = new_entry;  // Same entry, different index
            inbound_bucket->next = nat_table_inbound[ih];
            inbound_bucket->is_primary = false;  // This is a secondary reference
            nat_table_inbound[ih] = inbound_bucket;
            append_ln_to_log_file_nat_verbose("NAT: Added to inbound hash table (hash: %u)", ih);
        }
        
        nat_entry_count++;
        return new_entry;
    }
    else {  // INBOUND PACKET (WAN to LAN)
        existing = find_by_translated(details);
        
        if (existing) {
            // Found existing inbound translation
            inet_ntop(AF_INET, &existing->trans_ip, src_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &existing->orig_ip, dst_ip_str, INET_ADDRSTRLEN);
            
            append_ln_to_log_file_nat_verbose("NAT: Using existing inbound entry: %s:%u -> %s:%u",
                                    src_ip_str, existing->trans_port_host,
                                    dst_ip_str, existing->orig_port_host);
            return existing;
        }
        
        // No existing entry
        append_ln_to_log_file_nat_verbose("NAT: No existing inbound entry for %s:%u",
                                inet_ntoa(*(struct in_addr*)&details->trans_ip),
                                details->trans_port_host);
        
        return NULL;
    }
}

// Remove a NAT entry from both hash tables
void remove_nat_entry(struct nat_entry *entry) {
    if (!entry) return;
    
    // Log removal
    char orig_ip[INET_ADDRSTRLEN], trans_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &entry->orig_ip, orig_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &entry->trans_ip, trans_ip, INET_ADDRSTRLEN);
    
    append_ln_to_log_file_nat_verbose("NAT: Removing entry: %s:%u -> %s:%u",
                            orig_ip, entry->orig_port_host, 
                            trans_ip, entry->trans_port_host);
    
    // Calculate hashes for both tables
    uint32_t oh = hash_key(entry->orig_ip, entry->orig_port_host, entry->protocol) % NAT_TABLE_SIZE;
    uint32_t ih = hash_key(entry->trans_ip, entry->trans_port_host, entry->protocol) % NAT_TABLE_SIZE;
    
    // Remove from outbound table
    struct nat_bucket *current = nat_table_outbound[oh];
    struct nat_bucket *prev = NULL;
    bool entry_freed = false;
    
    while (current) {
        if (current->entry == entry) {
            // Remove this bucket
            if (prev) {
                prev->next = current->next;
            } else {
                nat_table_outbound[oh] = current->next;
            }
            
            // Free NAT entry if this is the primary reference
            if (current->is_primary) {
                free(entry);
                entry_freed = true;
            }
            
            free(current);
            break;
        }
        prev = current;
        current = current->next;
    }
    
    // Remove from inbound table
    current = nat_table_inbound[ih];
    prev = NULL;
    
    while (current) {
        if (current->entry == entry) {
            // Remove this bucket
            if (prev) {
                prev->next = current->next;
            } else {
                nat_table_inbound[ih] = current->next;
            }
            
            // Free NAT entry if not already freed and this is primary
            if (!entry_freed && current->is_primary) {
                free(entry);
            }
            
            free(current);
            break;
        }
        prev = current;
        current = current->next;
    }
    
    nat_entry_count--;
}

// Cleanup expired NAT entries
// Updated Cleanup Function
void cleanup_expired_nat_entries() {
    time_t current_time = time(NULL);
    const int tcp_established_timeout = tcp_timeout;          // 4 hours (14400s)
    const int tcp_transitory_timeout = 240;                   // 4 minutes (RFC 5382)
    const int tcp_time_wait_timeout = 60;                     // 60 seconds (2MSL)
    
    int count_before = nat_entry_count;
    
    append_ln_to_log_file_nat_verbose("NAT: Running cleanup for expired entries");
    
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {
        struct nat_bucket *bucket = nat_table_outbound[i];
        
        while (bucket) {
            struct nat_bucket *next = bucket->next;
            struct nat_entry *entry = bucket->entry;
            int timeout = 0;
            
            // Priority 1: Custom timeout (RST/FIN cases)
            if (entry->custom_timeout > 0) {
                timeout = entry->custom_timeout;
            }
            // TCP state handling
            else if (entry->protocol == TCP_IP_TYPE) {  
                switch(entry->state) {
                    case NAT_TCP_ESTABLISHED:
                    case NAT_TCP_FIN_WAIT_1:
                    case NAT_TCP_FIN_WAIT_2:
                        timeout = tcp_established_timeout;
                        break;
                        
                    case NAT_TCP_SYN_SENT:
                    case NAT_TCP_SYN_RECEIVED:
                    case NAT_TCP_CLOSING:
                    case NAT_TCP_LAST_ACK:
                        timeout = tcp_transitory_timeout;
                        break;
                        
                    case NAT_TCP_TIME_WAIT:
                        timeout = tcp_time_wait_timeout;
                        break;
                        
                    default:
                        timeout = tcp_transitory_timeout;
                }
            }
            // Non-TCP protocols
            else if (entry->protocol == UDP_IP_TYPE) {
                timeout = udp_timeout;
            } else if (entry->protocol == ICMP_IP_TYPE) {
                timeout = icmp_timeout;
            } else {
                timeout = -1;  // Immediate cleanup for unknown protocols
            }
            
            // Validate and remove expired entries
            if (timeout > 0 && (current_time - entry->last_used > timeout)) {
                append_ln_to_log_file_nat_verbose("Expiring %s entry: state=%d last_used=%ld timeout=%d",
                    protocol_to_str(entry->protocol),
                    entry->state,
                    entry->last_used,
                    timeout);
                remove_nat_entry(entry);
            }
            
            bucket = next;
        }
    }
    
    append_ln_to_log_file_nat("NAT: Cleanup complete, removed %d, %d entries remaining", 
        count_before - nat_entry_count, nat_entry_count);
}

/// ARP:

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
    append_ln_to_log_file_nat_verbose("Buffering packet for target IP: %s", inet_ntoa(*(struct in_addr *)&target_ip));
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
    append_ln_to_log_file_nat_verbose("Sent ARP request for %s via %s interface",
                        inet_ntoa(target_addr),
                        (direction == OUTBOUND) ? "WAN" : "LAN");
    
    free(frame);  // Clean up allocated memory
}


void handle_arp_reply(uint8_t *frame, ssize_t len) {

    const struct arp_header *arp = extract_arp_header_from_ethernet_frame(frame);
    
    // Update cache
    arp_cache_update(arp->sender_ip, (uint8_t *)arp->sender_mac);
    
    append_ln_to_log_file_nat_verbose("Handling ARP reply...");
    append_ln_to_log_file_nat_verbose("Sender IP: %s", inet_ntoa(*(struct in_addr *)&arp->sender_ip));
    append_ln_to_log_file_nat_verbose("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                            arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2],
                            arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);
    
    // Process buffered packets
    append_ln_to_log_file_nat_verbose("Processing buffered packets...");
    struct arp_pending_packet *pkt, *tmp;
    HASH_FIND_INT(pending_packets, &arp->sender_ip, pkt);
    
    while(pkt) {
        struct ethernet_header *eth_header = (struct ethernet_header *)pkt->data;
        memcpy(eth_header->dst_mac, arp->sender_mac, 6);
        append_ln_to_log_file_nat_verbose("Sending buffered packet to %s", inet_ntoa(*(struct in_addr *)&arp->sender_ip));

        send_raw_frame(arp->sender_mac, ETH_P_IP, pkt->data, pkt->len, pkt->direction);
        
        tmp = pkt;  // Save current packet before deletion
        HASH_DEL(pending_packets, pkt);
        free(tmp->data);
        free(tmp);
        
        // Look for more packets for this IP
        HASH_FIND_INT(pending_packets, &arp->sender_ip, pkt);
    }
}

void print_arp_cache() {
    struct arp_cache_entry *entry, *tmp;
    char buffer[256];
    int len;

    HASH_ITER(hh, arp_cache, entry, tmp) {
        struct in_addr ip_addr = {.s_addr = entry->ip};
        len = snprintf(buffer, sizeof(buffer), "IP: %s, MAC: %02x:%02x:%02x:%02x:%02x:%02x, Last Updated: %ld\n",
                       inet_ntoa(ip_addr),
                       entry->mac[0], entry->mac[1], entry->mac[2],
                       entry->mac[3], entry->mac[4], entry->mac[5],
                       entry->last_updated);
        write(tx_fd, buffer, len);
    }
}

void clear_arp_cache() {
    struct arp_cache_entry *current_entry, *tmp;
    
    HASH_ITER(hh, arp_cache, current_entry, tmp) {
        HASH_DEL(arp_cache, current_entry);  
        free(current_entry);
    }
    
    char clear_msg[] = "ARP cache cleared successfully\n";
    write(tx_fd, clear_msg, sizeof(clear_msg)-1);
}

/// End of ARP



/// Utility Functions:
int is_reserved_port(uint16_t port) {
    for (size_t i = 0; i < sizeof(port_list)/sizeof(port_list[0]); i++) {
        if (port_list[i] == port) {
            return 1;
        }
    }
    return 0;
}

int is_local_bound_packet(uint32_t dst_ip, uint32_t src_ip) {
    uint32_t src_ip_host = ntohl(src_ip);
    uint32_t dst_ip_host = ntohl(dst_ip);

    // Print src and dst IPs in str
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_ip_host, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_ip_host, dst_ip_str, INET_ADDRSTRLEN);
    append_ln_to_log_file_nat_verbose("Packet Details outbound: %s -> %s", src_ip_str, dst_ip_str);
    
    // TODO: Fix this, 192.168.10.xx, 10.0.0.xx
    int is_local = (dst_ip_host & MASK) == (src_ip_host & MASK);
    // append_ln_to_log_file_nat_verbose("NAT: dst_ip & 0xFFFFFF00: %d", (dst_ip_host & 0xFFFFFF00));
    // append_ln_to_log_file_nat_verbose("NAT: src_ip & 0xFFFFFF00: %d", (src_ip_host & 0xFFFFFF00));
    return is_local;
}

// Checks if src MAC address is of the WAN iface.
int is_packet_outgoing(struct ethernet_header *eth_header){
    // wan_machine_mac is loaded at the start of the application.
    return memcmp(eth_header->src_mac, wan_machine_mac, 6) == 0;
}

// Checks if src MAC address is of the WAN iface.
int is_packet_inbound(struct ethernet_header *eth_header){
    // wan_machine_mac is loaded at the start of the application.
    return memcmp(eth_header->src_mac, lan_machine_mac, 6) == 0;
}

// Allocates a port incrementally.
uint16_t allocate_port(uint8_t protocol) {  
    static uint16_t next_port = 32768;      // Start in ephemeral range (32768-60999)  
    uint16_t candidate = next_port++;  

    // Check for port collision  
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {  
        for (struct nat_bucket *b = nat_table_outbound[i]; b != NULL; b = b->next) {  
            if (b->entry->trans_port_host == candidate &&  
                b->entry->protocol == protocol) {  
                candidate = next_port++;    // Collision → try next port  
                i = -1;                     // Restart search  
                break;
            }
        }
    }
    append_ln_to_log_file_nat_verbose("Allocated port: %u", candidate);

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

void get_machine_ip(const char *iface, char *gateway_ip, size_t size) {

    
    int temp_sock;  // Temporary socket for IP lookup
    struct ifreq ifr;

    // Get IP address using a temporary socket
    if((temp_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        append_ln_to_log_file_nat_verbose("Temp socket creation failed on iface %s.", iface);
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if(ioctl(temp_sock, SIOCGIFADDR, &ifr) < 0) {
        append_ln_to_log_file_nat_verbose("IP address retrieval failed on iface %s. Continuing without it.", iface);
        close(temp_sock);
    }
    
    // Store IP
    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    uint32_t ip_buffer = ip_addr->sin_addr.s_addr;
    
    inet_ntop(AF_INET, &ip_buffer, gateway_ip, INET_ADDRSTRLEN);
    close(temp_sock);
}

/// LOGGING:

// Sends binary content to router.
void send_to_router(unsigned char *msg, int msg_len) {
    write(tx_fd, msg, msg_len);
}

char* time_to_fstr(time_t _time, char buffer[26]){
    strftime(*buffer, 26, "%Y-%m-%d %H:%M:%S", localtime(&_time));
    return buffer;
}

static void clear_log_file() {
    FILE *log_file = fopen(log_file_path, "w");
    if (log_file) {
        fprintf(log_file, "\n\n");
        fclose(log_file);
        append_ln_to_log_file_nat_verbose("Log file cleared.");
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
            append_ln_to_log_file_nat_verbose("Log file size exceeded %d bytes.", MAX_LOG_SIZE);
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
    append_ln_to_log_file_nat_verbose("[Info] WAN gateway IP: %s", inet_ntoa(*(struct in_addr *)&wan_gateway_ip));
    send_arp_request(wan_gateway_ip, OUTBOUND); // Send ARP request to get MAC address of the gateway. This will arrive on handle inbound.

    get_machine_ip(DEFAULT_WAN_IFACE, wan_machine_ip_str, sizeof(wan_machine_ip_str));
    get_machine_ip(DEFAULT_LAN_IFACE, lan_machine_ip_str, sizeof(lan_machine_ip_str));
    
    struct in_addr addr;
    inet_pton(AF_INET, wan_machine_ip_str, &addr);
    wan_machine_ip = addr.s_addr;

    

    append_ln_to_log_file_nat_verbose("[info] WAN iface Machine IP: %s", wan_machine_ip_str);
    append_ln_to_log_file_nat_verbose("[info] LAN iface Machine IP: %s", lan_machine_ip_str);
    
    append_ln_to_log_file_nat_verbose("[info] WAN and LAN interfaces ready.");
    append_ln_to_log_file_nat_verbose(NULL);

    // If failed, throw a critical error to router and log it.
}


/// Packet processing:

int init_socket(char *iface_name){
    
    struct sockaddr_ll saddr;
    struct ifreq ifr;
    int raw_sock;

    if((raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        append_ln_to_log_file_nat_verbose("NAT: Socket creation failed.");

        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
    if(ioctl(raw_sock, SIOCGIFINDEX, &ifr) < 0) {
        append_ln_to_log_file_nat_verbose("NAT: Interface config failed.");
        close(raw_sock);
        exit(EXIT_FAILURE);
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_ifindex = ifr.ifr_ifindex;
    saddr.sll_protocol = htons(ETH_P_ALL);
    
    if(bind(raw_sock, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        append_ln_to_log_file_nat_verbose("NAT: Bind failed.");
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

void send_icmp_time_exceeded(struct ipv4_header *ip_header, struct raw_ethernet_frame *eth_frame, packet_direction_t direction) {
    uint8_t icmp_buffer[sizeof(struct ethernet_header) + sizeof(struct ipv4_header) + sizeof(struct icmp_error)];

    // Setup Ethernet header
    struct ethernet_header *eth = (struct ethernet_header *)icmp_buffer;
    memcpy(eth->dst_mac, eth_frame->header.src_mac, 6);
    memcpy(eth->src_mac, (direction == OUTBOUND) ? lan_machine_mac : wan_machine_mac, 6);
    eth->type = htons(IPV4_ETH_TYPE);

    // Setup IP header for ICMP response
    struct ipv4_header *icmp_ip = (struct ipv4_header *)(icmp_buffer + sizeof(struct ethernet_header));
    *icmp_ip = (struct ipv4_header){
        .version = 4, .ihl = 5, .ttl = 64,
        .protocol = ICMP_IP_TYPE,
        .saddr = (direction == OUTBOUND) ? lan_machine_ip : wan_machine_ip,
        .daddr = ip_header->saddr
    };

    // Setup ICMP Time Exceeded message
    struct icmp_error *icmp_err = (struct icmp_error *)(icmp_buffer + sizeof(struct ethernet_header) + sizeof(struct ipv4_header));
    icmp_err->type = 11;  // Time Exceeded
    icmp_err->code = 0;   // TTL exceeded in transit
    icmp_err->checksum = 0;

    // Include original IP header + 8 bytes of original data
    memcpy(icmp_err->orig_header, ip_header, sizeof(icmp_err->orig_header));

    // Calculate ICMP checksum
    icmp_err->checksum = compute_checksum(icmp_err, sizeof(struct icmp_error));

    // Calculate IP header length & checksum
    icmp_ip->tot_len = htons(sizeof(struct ipv4_header) + sizeof(struct icmp_error));
    update_ip_checksum(icmp_ip);

    // Send the ICMP Time Exceeded message back to source
    send_raw_frame(eth->dst_mac, IPV4_ETH_TYPE, icmp_buffer, sizeof(icmp_buffer), (direction == OUTBOUND) ? INBOUND : OUTBOUND);

    append_ln_to_log_file_nat_verbose("[TTL Expired] Dropped packet and sent ICMP Time Exceeded");
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

uint8_t validate_udp_checksum(struct ipv4_header *ip_header, struct udp_header *udp_header, const uint8_t *payload, size_t payload_len) {
    // Checksum validation
    uint16_t received_checksum = ntohs(udp_header->check);
    udp_header->check = 0;
    uint16_t checksum = compute_udp_checksum(ip_header, udp_header, payload, payload_len);
    if (checksum == 0) checksum = 0xFFFF;
    append_ln_to_log_file_nat_verbose("UDP checksum before any change: 0x%04" PRIx16 ", received checksum value: 0x%04" PRIx16, 
                                ntohs(checksum), received_checksum);
    if (ntohs(checksum) != received_checksum) {
        return 0;
    }
    append_ln_to_log_file_nat_verbose("NAT: UDP checksum validation passed.");
    udp_header->check = received_checksum;
    return 1;
}

// Flow: From LAN to WAN => 192.168.20.2 -> 172.217.215.102
void handle_outbound_packet(unsigned char *buffer, ssize_t len) {
    
    // Get ethernet frame and header.
    struct raw_ethernet_frame *eth_frame = extract_ethernet_frame(buffer);
    struct ethernet_header *eth_header = &eth_frame->header;

    append_ln_to_log_file_nat_verbose("Handle outbound: Ethernet header type: %u", ntohs(eth_header->type));
    
    uint16_t eth_type_host = ntohs(eth_header->type);
    if (eth_type_host == ARP_ETH_TYPE){         // Process ARP reply.
        handle_arp_reply(buffer, len);
    }
    else if (eth_type_host != IPV4_ETH_TYPE){   // Anything other than IPv4 SHALL NOT PASS!
        return;
    }    
    
    // Get IP packet and header.
    struct ipv4_packet *ip_packet = extract_ipv4_packet_from_eth_payload(&eth_frame->payload);
    struct ipv4_header *ip_header = &ip_packet->header;
    
    if(ip_header->version != 4) return;         // Anything other than IPv4 SHALL NOT PASS!
    
    uint16_t translated_dport, translated_sport;

    // Is destination IP in the same subnet? Don't process it.
    if (is_local_bound_packet(ip_header->daddr, ip_header->saddr) == 1){
        append_ln_to_log_file_nat_verbose("NAT: Packet is local bound, not processing.");
        append_ln_to_log_file_nat_verbose(NULL);
        return;
    }

    // Create the NAT entry.
    struct nat_entry *received_packet_details = malloc(sizeof(struct nat_entry));

    received_packet_details->protocol = ip_header->protocol;
    received_packet_details->orig_ip = ip_header->saddr;        // Stored as network byte order.
    
    struct nat_entry *translated_nat_entry;

    // Extraction of ip and port.
    switch (ip_header->protocol){
        case ICMP_IP_TYPE: 
        {
            const struct icmp_header *icmp_h = extract_icmp_header_from_ipv4_packet(ip_packet);
    
            // Handle ICMP Query Messages (Echo Request)
            if (icmp_h->type == 8) {  // Echo Request
                const struct icmp_echo *icmp_echo_packet = extract_icmp_echo_header_from_ipv4_packet(ip_packet);
                received_packet_details->orig_port_host = ntohs(icmp_echo_packet->identifier);

                // Create NAT entry using ICMP identifier as "port"
                struct nat_entry *translated_nat_entry = enrich_entry(received_packet_details, OUTBOUND);
                if (!translated_nat_entry) {
                    append_ln_to_log_file_nat_verbose("[Error] Failed to create ICMP NAT entry");
                    return;
                }

                // Perform translation
                struct icmp_echo *icmp_echo_h = (struct icmp_echo *)icmp_h;
                icmp_echo_h->identifier = htons(translated_nat_entry->trans_port_host);
                ip_header->saddr = translated_nat_entry->trans_ip;

                // Recalculate checksums
                icmp_echo_h->checksum = 0;
                icmp_echo_h->checksum = compute_checksum(icmp_echo_h, 
                    ntohs(ip_header->tot_len) - (ip_header->ihl * 4));
            }
            // Handle ICMP Error Messages
            else if (icmp_h->type == 3 || icmp_h->type == 11 || icmp_h->type == 12) {
                const struct icmp_error *icmp_error_packet = extract_icmp_error_header_from_ipv4_packet(ip_packet);
                struct ipv4_header *orig_ip_hdr = (struct ipv4_header*)icmp_error_packet->orig_header;
        
                // Only translate if embedded packet was from NAT
                if (orig_ip_hdr->protocol == IPPROTO_TCP || orig_ip_hdr->protocol == IPPROTO_UDP) {
                    struct nat_entry embedded_entry = {
                        .trans_ip = orig_ip_hdr->saddr,
                        .trans_port_host = (orig_ip_hdr->protocol == IPPROTO_TCP) ? 
                            ntohs(((struct tcp_header*)(orig_ip_hdr + 1))->sport) :
                            ntohs(((struct udp_header*)(orig_ip_hdr + 1))->sport),
                        .protocol = orig_ip_hdr->protocol
                    };

                    // Find original mapping
                    struct nat_entry *original_entry = find_by_translated(&embedded_entry);
                    if (original_entry) {
                        // Translate embedded header
                        orig_ip_hdr->saddr = original_entry->orig_ip;
                        if (orig_ip_hdr->protocol == IPPROTO_TCP) {
                            ((struct tcp_header*)(orig_ip_hdr + 1))->sport = htons(original_entry->orig_port_host);
                        } else {
                            ((struct udp_header*)(orig_ip_hdr + 1))->sport = htons(original_entry->orig_port_host);
                        }
                    }
                }
            }
            break;
        }

        case TCP_IP_TYPE:
        {
            append_ln_to_log_file_nat_verbose("NAT: Outbound TCP packet.");

            struct tcp_header *tcp_h = extract_tcp_header_from_ipv4_packet(ip_packet);
    
            // Validate TCP header length
            uint16_t dorf = ntohs(tcp_h->data_offset_reserved_flags);
            uint16_t doff = (dorf >> 12) & 0xF;
            uint16_t tcp_header_len = doff * 4; // Convert to bytes
                
            if (tcp_header_len < sizeof(struct tcp_header) || tcp_header_len > 60) {
                append_ln_to_log_file_nat_verbose("[Error] Invalid TCP header length: %zu", tcp_header_len);
                append_ln_to_log_file_nat_verbose("data_offset_reserved_flags (hex): 0x%04x\n", dorf);
                append_ln_to_log_file_nat_verbose(NULL);
                return;
            }

            // Calculate payload parameters
            uint16_t ip_total_len = ntohs(ip_header->tot_len);
            uint16_t ip_header_len = ip_header->ihl * 4;
            uint16_t ip_payload_len = ip_total_len - ip_header_len;
            uint16_t tcp_payload_len = ip_payload_len - tcp_header_len;
            const uint8_t *tcp_payload = (const uint8_t*)tcp_h + tcp_header_len;

            append_ln_to_log_file_nat("Outbound TCP payload length: %zu - %zu - %zu = %zu", ip_payload_len, ip_header_len, tcp_header_len, tcp_payload_len);
            // Validate payload access
            if ((tcp_payload + tcp_payload_len) > (buffer + len)) {
                append_ln_to_log_file_nat_verbose("[Error] TCP payload exceeds packet buffer");
                append_ln_to_log_file_nat_verbose(NULL);
                return;
            }

            append_ln_to_log_file_nat_verbose("Packet Details outbound: %d -> %d", ntohs(tcp_h->sport), ntohs(tcp_h->dport));

            // Verify original checksum before translation
            if (false){
            uint16_t received_check = tcp_h->check;
            tcp_h->check = 0;
            uint16_t calculated_check = compute_tcp_checksum(ip_header, tcp_header_len, tcp_h, tcp_payload, tcp_payload_len);
    
            if (calculated_check != received_check && received_check != 0) {
                append_ln_to_log_file_nat_verbose("[Error] Invalid TCP checksum: recv=0x%04x calc=0x%04x",
                                        ntohs(received_check), ntohs(calculated_check));
                append_ln_to_log_file_nat_verbose(NULL);
                return;
            }
            append_ln_to_log_file_nat_verbose("TCP checksum validated");
            }
            // Create NAT entry
            received_packet_details->orig_port_host = ntohs(tcp_h->sport);

            // Get/Create translation entry
            struct nat_entry *translated_nat_entry = enrich_entry(received_packet_details, OUTBOUND);
            if (!translated_nat_entry) {
                append_ln_to_log_file_nat_verbose("[Error] Failed to create NAT entry");
                return;
            }

            // Perform translation
            ip_header->saddr = translated_nat_entry->trans_ip;
            tcp_h->sport = htons(translated_nat_entry->trans_port_host);

            // Recalculate TCP checksum
            tcp_h->check = 0;
            uint16_t tcp_check = compute_tcp_checksum(ip_header, tcp_header_len, tcp_h, tcp_payload, tcp_payload_len);
            tcp_h->check = tcp_check;
                
            // RFC 5382 connection tracking.

            uint16_t flags = TCP_FLAGS(tcp_h->data_offset_reserved_flags);
            
            // ACK Handling
            if (flags & (1 << 4)) {
                if (translated_nat_entry->state == NAT_TCP_SYN_RECEIVED) {
                    translated_nat_entry->state = NAT_TCP_ESTABLISHED;
                }
                translated_nat_entry->last_used = time(NULL);
            }

            // RST Handling
            if (flags & (1 << 6)) {
                translated_nat_entry->state = NAT_TCP_CLOSING;
                translated_nat_entry->custom_timeout = 10;  // Fast cleanup for reset connections
            }

            // SYN Handling
            if (flags & (1 << 7)) {
                if (translated_nat_entry->state == NAT_TCP_ESTABLISHED) {
                    translated_nat_entry->state = NAT_TCP_CLOSING;
                }
            }

            // FIN Handling
            if (flags & (1 << 8)) {
                switch(translated_nat_entry->state) {
                    case NAT_TCP_ESTABLISHED:
                        translated_nat_entry->state = NAT_TCP_FIN_WAIT_1;
                        break;
                    case NAT_TCP_FIN_WAIT_1:
                        translated_nat_entry->state = NAT_TCP_CLOSING;
                        break;
                    case NAT_TCP_FIN_WAIT_2:
                        translated_nat_entry->state = NAT_TCP_TIME_WAIT;
                        break;
                }
                translated_nat_entry->last_used = time(NULL);  // Reset timer on state change
            }

            // Final ACK Handling
            if (flags & (1 << 4)) {
                switch(translated_nat_entry->state) {
                    case NAT_TCP_FIN_WAIT_1:
                        translated_nat_entry->state = NAT_TCP_FIN_WAIT_2;
                        break;
                    case NAT_TCP_CLOSING:
                        translated_nat_entry->state = NAT_TCP_TIME_WAIT;
                        break;
                }
            }

            // Verification
            append_ln_to_log_file_nat_verbose("TCP checksum: 0x%04x (calculated)", ntohs(tcp_check));
            append_ln_to_log_file_nat_verbose("NAT mapping: %u -> %u", 
                ntohs(received_packet_details->orig_port_host), 
                ntohs(translated_nat_entry->trans_port_host));

            break;
        }


        case UDP_IP_TYPE:{
            // Extraction
            append_ln_to_log_file_nat_verbose("NAT: Outbound UDP packet.");

            struct udp_header *udp_h = extract_udp_header_from_ipv4_packet(ip_packet);
            uint16_t udp_len_host = ntohs(udp_h->len);
        
            size_t udp_payload_len = (udp_len_host > sizeof(struct udp_header)) 
                               ? (udp_len_host - sizeof(struct udp_header)) 
                               : 0;

            
            const uint8_t *udp_payload = (const uint8_t *)(udp_h + 1); // Point to payload after UDP header

            if (!validate_udp_checksum(ip_header, udp_h, udp_payload, udp_payload_len)){
                append_ln_to_log_file_nat_verbose("Outbound: UDP checksum validation failed. Dropping packet.");
                return;
            }

            append_ln_to_log_file_nat_verbose("Packet Details outbound: %d -> %d", ntohs(udp_h->sport), ntohs(udp_h->dport));

            received_packet_details->orig_port_host = ntohs(udp_h->sport);

            // Translation:

            translated_nat_entry = enrich_entry(received_packet_details, OUTBOUND);
            if (translated_nat_entry == NULL) {
                append_ln_to_log_file_nat_verbose("[Error] Failed to enrich entry.");
                return;
            }   
            ip_header->saddr = translated_nat_entry->trans_ip;         
            udp_h->sport = htons(translated_nat_entry->trans_port_host);
            translated_sport = ntohs(udp_h->sport);            // Only used for logging.
            translated_dport = ntohs(udp_h->dport);            // Only used for logging.
        
            // Recompute checksum with new ports and IP
            udp_h->check = 0;
            uint16_t udp_check = compute_udp_checksum(ip_header, udp_h, udp_payload, udp_payload_len);
            if (udp_check == 0) udp_check = 0xFFFF;  // Handle zero case
        
            udp_h->check = udp_check;
            break;
        }
        default:
            // Unsupported protocol - don't process.            
            return;
    }

    append_ln_to_log_file_nat_verbose("Outbound Packet details:");

    unsigned char *bytes = (unsigned char *)&ip_header->saddr;
    append_ln_to_log_file_nat_verbose("LAN IP: %d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

    append_ln_to_log_file_nat_verbose("LAN Port: %u", translated_sport);
    bytes = (unsigned char *)&ip_header->daddr;
    append_ln_to_log_file_nat_verbose("WAN IP: %d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    append_ln_to_log_file_nat_verbose("WAN Port: %u", translated_dport);
    append_ln_to_log_file_nat_verbose("Protocol: %u", ip_header->protocol);

    
    // Recalculate IP checksum
    ip_header->check = 0; // Reset checksum before recalculation
    ip_header->check = compute_checksum(ip_header, ip_header->ihl * 4);
    append_ln_to_log_file_nat_verbose("NAT: Updated IP checksum: %u", ip_header->check);


    // Update Ethernet headers for WAN interface
    memcpy(eth_header->src_mac, wan_machine_mac, 6);
    
    // Check ARP cache for gateway MAC
    struct arp_cache_entry *entry;
    HASH_FIND_INT(arp_cache, &wan_gateway_ip, entry);
    
    if (entry) {
        // MAC known - send immediately
        memcpy(eth_header->dst_mac, entry->mac, 6);
        send_raw_frame(entry->mac, ETH_P_IP, eth_frame, len, OUTBOUND);
        append_ln_to_log_file_nat_verbose("NAT: Sent packet to known MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                                entry->mac[0], entry->mac[1], entry->mac[2],
                                entry->mac[3], entry->mac[4], entry->mac[5]);
    } else {
        // Buffer translated packet and request MAC
        buffer_packet(eth_frame, len, wan_gateway_ip, OUTBOUND);
        send_arp_request(wan_gateway_ip, OUTBOUND);
        append_ln_to_log_file_nat_verbose("NAT: Buffered packet awaiting ARP resolution");
    }

    append_ln_to_log_file_nat_verbose(NULL);

    // https://www.rfc-editor.org/rfc/rfc4787#section-4.3 for timeouts.
    // For UDP, only update for an outbound packet.
    // ICMP inbound packets are either failed IP connection, or a ping test, just map it and update the timeout to 60 sec.
    // For ICMP outbound packets, update the NAT table.
    
}

void handle_inbound_packet(unsigned char *buffer, ssize_t len) {
    append_ln_to_log_file_nat_verbose("NAT: Inbound frame of size %d.", len);
    // Get ethernet frame and header.
    struct raw_ethernet_frame *eth_frame = extract_ethernet_frame(buffer);
    struct ethernet_header *eth_header = &eth_frame->header;

    append_ln_to_log_file_nat_verbose("NAT: Ethernet header type: %u", ntohs(eth_header->type));

    if (is_packet_outgoing(eth_header))
    {
        append_ln_to_log_file_nat_verbose("[Verbose] [info] Outbound packet, not processing.");
        append_ln_to_log_file_nat_verbose(NULL);
        return;
    }

    uint16_t eth_type_host = ntohs(eth_header->type);
    if (eth_type_host == ARP_ETH_TYPE){         // Process ARP reply.
        handle_arp_reply(buffer, len);
    }
    else if (eth_type_host != IPV4_ETH_TYPE){   // Anything other than IPv4 SHALL NOT PASS!
        append_ln_to_log_file_nat_verbose("Packet Type not supported.");
        append_ln_to_log_file_nat_verbose(NULL);
        return;
    }
    
    // Get IP packet and header.
    struct ipv4_packet *ip_packet = extract_ipv4_packet_from_eth_payload(&eth_frame->payload);
    struct ipv4_header *ip_header = extract_ipv4_header_from_ipv4_packet(ip_packet);

    if(ip_header->version != 4) return;                                                 // Anything other than IPv4 SHALL NOT PASS!
    
    uint16_t sport;
    struct nat_entry *received_packet_details = malloc(sizeof(struct nat_entry));

    received_packet_details->trans_ip = ip_header->daddr;       // The source address is machine's ip.
    received_packet_details->protocol = ip_header->protocol;    // IP Protocol.
        
    // Print src and dst IPs in str
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_header->saddr, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &received_packet_details->trans_ip, dst_ip_str, INET_ADDRSTRLEN);
    append_ln_to_log_file_nat_verbose("Packet Details inbound: %s -> %s", src_ip_str, dst_ip_str);

    switch (ip_header->protocol){
        case ICMP_IP_TYPE: 
        {
            const struct icmp_header *icmp_h = extract_icmp_header_from_ipv4_packet(ip_packet);
    
            // Handle ICMP Echo Reply
            if (icmp_h->type == 0) {  // Echo Reply
                const struct icmp_echo *icmp_echo_packet = extract_icmp_echo_header_from_ipv4_packet(ip_packet);
                received_packet_details->trans_port_host = ntohs(icmp_echo_packet->identifier);

                // Look up original mapping
                struct nat_entry *translated_nat_entry = enrich_entry(received_packet_details, INBOUND);
                if (!translated_nat_entry) {
                    append_ln_to_log_file_nat_verbose("[Error] No NAT entry for ICMP ID %d", 
                        received_packet_details->trans_port_host);
                    return;
                }

                // Translate back to original
                struct icmp_echo *icmp_echo_h = (struct icmp_echo *)icmp_h;
                icmp_echo_h->identifier = htons(translated_nat_entry->orig_port_host);
                ip_header->daddr = translated_nat_entry->orig_ip;

                // Recalculate checksums
                icmp_echo_h->checksum = 0;
                icmp_echo_h->checksum = compute_checksum(icmp_echo_h, 
                    ntohs(ip_header->tot_len) - (ip_header->ihl * 4));
            }
            // Handle ICMP Error Messages
            else if (icmp_h->type == 3 || icmp_h->type == 11 || icmp_h->type == 12) {
                const struct icmp_error *icmp_error_packet = extract_icmp_error_header_from_ipv4_packet(ip_packet);
                struct ipv4_header *orig_ip_hdr = (struct ipv4_header*)icmp_error_packet->orig_header;

                // Only process embedded TCP/UDP packets
                if (orig_ip_hdr->protocol == IPPROTO_TCP || orig_ip_hdr->protocol == IPPROTO_UDP) {
                    struct nat_entry embedded_entry = {
                        .trans_ip = orig_ip_hdr->daddr,
                        .trans_port_host = (orig_ip_hdr->protocol == IPPROTO_TCP) ? 
                            ntohs(((struct tcp_header*)(orig_ip_hdr + 1))->dport) :
                            ntohs(((struct udp_header*)(orig_ip_hdr + 1))->dport),
                        .protocol = orig_ip_hdr->protocol
                    };

                    // Find original mapping
                    struct nat_entry *original_entry = find_by_translated(&embedded_entry);
                    if (original_entry) {
                        // Translate embedded destination address
                        orig_ip_hdr->daddr = original_entry->trans_ip;
                        if (orig_ip_hdr->protocol == IPPROTO_TCP) {
                            ((struct tcp_header*)(orig_ip_hdr + 1))->dport = htons(original_entry->trans_port_host);
                        } else {
                            ((struct udp_header*)(orig_ip_hdr + 1))->dport = htons(original_entry->trans_port_host);
                        }
                    }
                }
            }
            else {
                append_ln_to_log_file_nat_verbose("Unsupported ICMP type: %d", icmp_h->type);
                return;
            }
            break;
        }
        case TCP_IP_TYPE:
        {
            struct tcp_header *tcp_h = extract_tcp_header_from_ipv4_packet(ip_packet);
            append_ln_to_log_file_nat_verbose("NAT: Inbound TCP packet.");
            
            append_ln_to_log_file_nat_verbose("Packet Details inbound: %d -> %d", ntohs(tcp_h->sport), ntohs(tcp_h->dport));
                        
            // Filters for other services.
            if (is_reserved_port(ntohs(tcp_h->dport))){
                append_ln_to_log_file_nat("DROPPED by rule: TCP packet has a reserved inbound port %d.", ntohs(tcp_h->dport));
                append_ln_to_log_file_nat(NULL);
                return;
            }
            
            // Validate TCP header length
            if (!tcp_h->data_offset_reserved_flags) {
                append_ln_to_log_file_nat("[Error] Failed to extract TCP header.");
                append_ln_to_log_file_nat(NULL);
                return;
            }
            
            uint16_t dorf = ntohs(tcp_h->data_offset_reserved_flags);
            uint16_t doff = (dorf >> 12) & 0xF;
            uint8_t tcp_header_len = doff * 4; // Convert to bytes
            if (tcp_header_len < sizeof(struct tcp_header) || tcp_header_len > 60) {
                append_ln_to_log_file_nat_verbose("[Error] Invalid TCP header length: %zu", tcp_header_len);
                append_ln_to_log_file_nat_verbose("data_offset_reserved_flags (hex): 0x%04x\n", dorf);
                append_ln_to_log_file_nat_verbose(NULL);
                return;
            }

            // Calculate payload parameters
            uint16_t ip_payload_len = ntohs(ip_header->tot_len) - (ip_header->ihl * 4);
            uint16_t tcp_payload_len = ip_payload_len - tcp_header_len;
            const uint8_t *tcp_payload = (const uint8_t*)tcp_h + tcp_header_len;

            // Validate payload access
            if ((tcp_payload + tcp_payload_len) > (buffer + len)) {
                append_ln_to_log_file_nat("[Error] TCP payload exceeds packet buffer");
                return;
            }

            // Verify original checksum before translation
            uint16_t received_check = tcp_h->check;
            tcp_h->check = 0;
            uint16_t calculated_check = compute_tcp_checksum(ip_header, tcp_header_len, tcp_h, tcp_payload, tcp_payload_len);
    
            if (calculated_check != received_check && received_check != 0) {
                append_ln_to_log_file_nat("[Error] Invalid TCP checksum: recv=0x%04x calc=0x%04x",
                                        ntohs(received_check), ntohs(calculated_check));
                append_ln_to_log_file_nat(NULL);
                return;
            }
            append_ln_to_log_file_nat_verbose("TCP checksum validated");

            // Get NAT translation
            received_packet_details->trans_port_host = ntohs(tcp_h->dport);
            struct nat_entry *enriched_entry = enrich_entry(received_packet_details, INBOUND);
            if (!enriched_entry) {
                append_ln_to_log_file_nat("[Error] No NAT entry for TCP port %d", ntohs(tcp_h->dport));
                append_ln_to_log_file_nat(NULL);
                return;
            }

            // Perform translation
            ip_header->daddr = enriched_entry->orig_ip;
            tcp_h->dport = htons(enriched_entry->orig_port_host);

            // Recompute checksums
            tcp_h->check = 0;
            uint16_t new_tcp_check = compute_tcp_checksum(ip_header, tcp_header_len, tcp_h, tcp_payload, tcp_payload_len);
            tcp_h->check = new_tcp_check;


            // RFC 5382 Connection Tracking (INBOUND)
            
            uint16_t flags = TCP_FLAGS(tcp_h->data_offset_reserved_flags);
            // ACK Handling
            if (flags & (1 << 4)) {
                if (enriched_entry->state == NAT_TCP_SYN_RECEIVED) {
                    enriched_entry->state = NAT_TCP_ESTABLISHED;
                }
                enriched_entry->last_used = time(NULL);
            }

            // RST Handling
            if (flags & (1 << 6)) {
                enriched_entry->state = NAT_TCP_CLOSING;
                enriched_entry->custom_timeout = 10;  // Fast cleanup for reset connections
            }

            // SYN Handling
            if (flags & (1 << 7)) {
                if (enriched_entry->state == NAT_TCP_ESTABLISHED) {
                    enriched_entry->state = NAT_TCP_CLOSING;
                }
            }

            // FIN Handling
            if (flags & (1 << 8)) {  // FIN from remote
                if (enriched_entry->state == NAT_TCP_ESTABLISHED) {
                    enriched_entry->state = NAT_TCP_FIN_WAIT_2;
                } else if (enriched_entry->state == NAT_TCP_FIN_WAIT_1) {
                    enriched_entry->state = NAT_TCP_CLOSING;
                }
                enriched_entry->last_used = time(NULL);
            }

            // Final ACK Handling
            if (flags & (1 << 4)) {
                switch(enriched_entry->state) {
                    case NAT_TCP_FIN_WAIT_1:
                        enriched_entry->state = NAT_TCP_FIN_WAIT_2;
                        break;
                    case NAT_TCP_CLOSING:
                        enriched_entry->state = NAT_TCP_TIME_WAIT;
                        break;
                }
            }

            append_ln_to_log_file_nat_verbose("TCP checksum updated: 0x%04x", ntohs(new_tcp_check));
            break;
        }
        case UDP_IP_TYPE:
        {
            // Extraction:
            struct udp_header *udp_h = extract_udp_header_from_ipv4_packet(ip_packet);
            append_ln_to_log_file_nat_verbose("Packet Details inbound: %d -> %d", ntohs(udp_h->sport), ntohs(udp_h->dport));

            uint16_t udp_len_host = ntohs(udp_h->len);

            size_t udp_payload_len = (udp_len_host > sizeof(struct udp_header)) 
                               ? (udp_len_host - sizeof(struct udp_header)) 
                               : 0;

            const uint8_t *udp_payload = (const uint8_t *)(udp_h + 1); // Point to payload after UDP header

            if (!validate_udp_checksum(ip_header, udp_h, udp_payload, udp_payload_len)){
                append_ln_to_log_file_nat_verbose("Inbound: UDP checksum validation failed. Dropping packet.");
                append_ln_to_log_file_nat_verbose(NULL);
                return;
            }

            // Filters for other services.
            if (is_reserved_port(ntohs(udp_h->sport))){
                append_ln_to_log_file_nat_verbose("DROPPED by rule: UDP packet has a reserved inbound port %d.", ntohs(udp_h->sport));
                append_ln_to_log_file_nat_verbose(NULL);
                return;
            }


            received_packet_details->trans_port_host = ntohs(udp_h->dport);

            char dest_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &received_packet_details->trans_ip, dest_ip_str, INET_ADDRSTRLEN);
            append_ln_to_log_file_nat_verbose("Inbound packet details: %s:%u (protocol: %u)", 
                                    dest_ip_str, received_packet_details->trans_port_host, received_packet_details->protocol);

            // Translation:
            struct nat_entry *enriched_nat_entry = enrich_entry(received_packet_details, INBOUND);

            if (enriched_nat_entry == NULL) {
                append_ln_to_log_file_nat_verbose("[Error] Failed to enrich entry.");
                append_ln_to_log_file_nat_verbose(NULL);
                return;
            }
            
            ip_header->daddr = enriched_nat_entry->orig_ip;
            udp_h->dport = htons(enriched_nat_entry->orig_port_host);

            // Recompute checksum with new ports and IP
            udp_h->check = 0;
            uint16_t udp_check = compute_udp_checksum(ip_header, udp_h, udp_payload, udp_payload_len);
            if (udp_check == 0) udp_check = 0xFFFF;  // Handle zero case
            udp_h->check = udp_check;

            break;
        }
        default:            // Unsupported protocol
            return;
    }
    
    // Recalculate IP checksum:
    ip_header->check = 0; // Reset checksum before recalculation
    ip_header->check = compute_checksum(ip_header, ip_header->ihl * 4);
    append_ln_to_log_file_nat_verbose("NAT: Updated IP checksum: %u", ip_header->check);

    // Update Ethernet headers for LAN interface
    
    memcpy(eth_header->src_mac, lan_machine_mac, 6);

    struct arp_cache_entry *entry;
    HASH_FIND_INT(arp_cache, &ip_header->daddr, entry);

    if (entry) {
        // MAC known - send immediately
        memcpy(eth_header->dst_mac, entry->mac, 6);
        send_raw_frame(entry->mac, ETH_P_IP, eth_frame, len, INBOUND);
        append_ln_to_log_file_nat_verbose("NAT: Sent packet to known MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                                entry->mac[0], entry->mac[1], entry->mac[2],
                                entry->mac[3], entry->mac[4], entry->mac[5]);
    } else {
        // Buffer translated packet and request MAC
        buffer_packet(eth_frame, len, wan_gateway_ip, INBOUND);
        send_arp_request(ip_header->daddr, INBOUND);
        append_ln_to_log_file_nat_verbose("NAT: Buffered packet awaiting ARP resolution");
    }
    append_ln_to_log_file_nat_verbose(NULL);
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
    
    append_ln_to_log_file_nat_verbose("NAT service started.");

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

        // Check if cleanup is due  
        if (now >= next_cleanup) {  
            // cleanup_expired_nat_entries();  
            // clean_log_file_if_full();
            last_cleanup = now;  
        }


        struct timeval tv = {.tv_sec = 1, .tv_usec = 0}; // 1 second select timeout.
        int ready = select(FD_SETSIZE, &read_fds, NULL, NULL, &tv);
        
        if(ready < 0) {
            append_ln_to_log_file_nat_verbose("[Critical] fd set: 'Select' error");
            break;
        }

        if (FD_ISSET(rx_fd, &read_fds)) {
            memset(command_from_router, 0, sizeof(command_from_router));
            int count = read(rx_fd, command_from_router, sizeof(command_from_router) - 1);
            
            // Process router command
            if (count <= 0 || strcmp(command_from_router, "shutdown") == 0) {
                append_ln_to_log_file_nat_verbose("Received shutdown command from router: Shutting down.");
                send_to_router("NAT: Shutting down.", 13);
                break;
            } 
            else if (strcmp(command_from_router, "clear logs") == 0) {
                clear_log_file();
                append_ln_to_log_file_nat_verbose("[Router Command] clear logs");
                append_ln_to_log_file_nat_verbose(NULL);
                write(tx_fd, "Cleared logs.\n", count);
            }
            else if (strcmp(command_from_router, "entries") == 0){
                print_nat_table();
            }
            else if (strcmp(command_from_router, "cleanup entries") == 0){
                cleanup_expired_nat_entries();
            }
            else if (strcmp(command_from_router, "clear") == 0){
                cleanup_all_nat_entries();
            }
            else if (strcmp(command_from_router, "arp cache") == 0){
                print_arp_cache();
            }
            else if (strcmp(command_from_router, "clear arp cache") == 0){
                clear_arp_cache();
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

    clear_arp_cache();
    cleanup_all_nat_entries();
    close(lan_raw);
    close(wan_raw);
    close(rx_fd);
    close(tx_fd);
    exit(EXIT_SUCCESS);
}
