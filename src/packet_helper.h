#ifndef PACKET_HELPER_H
#define PACKET_HELPER_H
#include <stdint.h>
#include <sys/types.h>

#pragma pack(push, 1)       // Lock the memory structure.

struct ethernet_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
};

struct raw_ethernet_frame {
    struct ethernet_header header;           // 14 bytes
    uint8_t payload;              // Max MTU
    uint32_t frame_check_sequence;      // 4 bytes. It uses CRC to calculate the checksum. Check whether FCS is received at layer 2. 
};

struct ipv4_header {
    uint8_t ihl:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct ipv4_packet{
    struct ipv4_header header;
    uint8_t* payload;
};

// Using only TCP header as we don't need TCP payload for router operations.
// Consider the memory size from the DATA OFFSET for checksum calculation.
struct tcp_header {
    uint16_t sport;     // SRC PORT
    uint16_t dport;     // DST PORT
    uint32_t seq;       // SEQ NUMBER
    uint32_t ack_seq;   // ACK NUMBER
    
    // Data offset and flags (16 bits total)
    uint16_t doff:4;    // Data offset (header length in 32-bit words)
    uint16_t res1:3;    // Reserved (unused)

    // FLAGS (9 bits):
    uint16_t ns:1;      // ECN Nonce (RFC 3540)
    uint16_t cwr:1;     // Congestion Window Reduced
    uint16_t ece:1;     // ECN-Echo
    uint16_t urg:1;     // URGENT
    uint16_t ack:1;     // ACKNOWLEDGEMENT
    uint16_t psh:1;     // PUSH
    uint16_t rst:1;     // RESET
    uint16_t syn:1;     // SYNCHORIZE
    uint16_t fin:1;     // FINISH
    
    uint16_t window;    // Receive window size
    uint16_t check;     // Checksum
    uint16_t urg_ptr;   // Urgent pointer (iff URG flag set)
    // OPTIONS start from here and are of arbitrary length, it's definied with padding. Handle them as necessary.
    // You can find the data start using data offset value.
};

// Using only UDP header as we don't need UDP payload for router operations.
// Consider the memory size from the DATA LENGTH for checksum calculation.
struct udp_header {
    uint16_t sport;     // SRC PORT
    uint16_t dport;     // DST PORT
    uint16_t len;       // DATA LENGTH
    uint16_t check;     // CHECKSUM
};

struct icmp_header {
    uint8_t type;      // ICMP type (e.g., 8 for Echo Request, 0 for Echo Reply)
    uint8_t code;      // ICMP code (subtype)
    uint16_t checksum; // Checksum (over header and data)
    uint32_t rest_of_header; // Varies by type/code (e.g., identifier and sequence for Echo)
    // Followed by data (variable length)
};

struct icmp_echo {  
    uint8_t type;  
    uint8_t code;  
    uint16_t checksum;  
    uint16_t identifier;  // Using this as port alternative.  
    uint16_t sequence;  
}; 

struct icmp_error {  
    // Common header  
    uint32_t unused;                // Zero-filled  
    uint8_t  orig_header[60];       // Could be a max of 60 bytes.
    uint8_t  orig_data[8];          // First 8 bytes of original payload  
}; 

struct arp_header {
    uint16_t hardware_type;    // Hardware Type (Ethernet = 1)
    uint16_t protocol_type;    // Protocol Type (IPv4 = 0x0800)
    uint8_t hardware_len;      // Hardware Address Length (6 bytes for MAC)
    uint8_t protocol_len;      // Protocol Address Length (4 bytes for IPv4)
    uint16_t operation;        // Operation code (1=request, 2=reply)
    uint8_t sender_mac[6];     // Sender's hardware address
    uint32_t sender_ip;        // Sender's IP address
    uint8_t target_mac[6];     // Target hardware address
    uint32_t target_ip;        // Target IP address
};

#pragma pack(pop)

// Extraction
const struct raw_ethernet_frame* extract_ethernet_frame(const uint8_t* network_buffer);
const struct ethernet_header* extract_ethernet_header_from_frame(const struct raw_ethernet_frame* frame);
const struct ipv4_packet* extract_ipv4_packet_from_eth_payload(const uint8_t* eth_payload);
const struct ipv4_header* extract_ipv4_header_from_ipv4_packet(const struct ipv4_packet* packet);
const struct tcp_header* extract_tcp_header_from_ipv4_packet(const struct ipv4_packet* packet);
const struct tcp_header* extract_tcp_header_from_ethernet_frame(const uint8_t* frame);
const struct udp_header* extract_udp_header_from_ipv4_packet(const struct ipv4_packet* packet);
const struct udp_header* extract_udp_header_from_ethernet_frame(const uint8_t* frame);
const struct icmp_header* extract_icmp_header_from_ipv4_packet(const struct ipv4_packet* packet);
const struct icmp_echo* extract_icmp_echo_header_from_ipv4_packet(const struct ipv4_packet* packet);
const struct icmp_error* extract_icmp_error_header_from_ipv4_packet(const struct ipv4_packet* packet);
const struct arp_header* extract_arp_header_from_ethernet_frame(const uint8_t* frame);
// End of Extraction


// Reassembly
void reassemble_ethernet(const struct raw_ethernet_frame frame, const struct ethernet_header* eth, 
                             const struct ipv4_header* ip, const struct tcp_header* transport_header, 
                             const uint8_t* payload, size_t payload_len);

uint16_t compute_checksum(const void* data, size_t len);
void update_ip_checksum(struct ipv4_header* ip);
void update_tcp_checksum(struct ipv4_header* ip, struct tcp_header* tcp, const uint8_t* payload, size_t payload_len);
void update_udp_checksum(struct ipv4_header* ip, struct udp_header* udp, const uint8_t* payload, size_t payload_len);

void update_ip_address(struct ipv4_header* ip, uint32_t new_src, uint32_t new_dst);
void update_tcp_ports(struct ipv4_header* ip, struct tcp_header* tcp, uint16_t new_src, uint16_t new_dst, const uint8_t* payload, size_t payload_len);
void update_udp_ports(struct ipv4_header* ip, struct udp_header* udp, uint16_t new_src, uint16_t new_dst, const uint8_t* payload, size_t payload_len);
// End of Reassembly

#endif /* PACKET_HELPER_h */
