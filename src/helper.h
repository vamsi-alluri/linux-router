#ifndef HELPER_H
#define HELPER_H
#include <stdint.h>
#include <sys/types.h>

#pragma pack(push, 1)       // Lock the memory structure.

struct eth_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
};

struct ipv4_header {
    uint8_t version:4;
    uint8_t ihl:4;
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
    uint16_t urg_ptr;   // Urgent pointer (if URG flag set)
    // OPTIONS start from here and are of arbitrary length, it's definied with padding. Handle them as necessary.
    // You can find the data start using data offset value.
};


struct udp_header {
    uint16_t sport;     // SRC PORT
    uint16_t dport;     // DST PORT
    uint16_t len;       // DATA LENGTH
    uint16_t check;     // CHECKSUM
};

#pragma pack(pop)

// Function prototypes
struct eth_header* extract_ethernet(const uint8_t* frame);
struct ipv4_header* extract_ipv4(const uint8_t* frame);
struct tcp_header* extract_tcp(const uint8_t* frame);
struct udp_header* extract_udp(const uint8_t* frame);

void reassemble_ethernet(uint8_t* frame, const struct eth_header* eth, 
							 const struct ipv4_header* ip,const void* transport_header, 
							 const uint8_t* payload, size_t payload_len);

uint16_t compute_checksum(const void* data, size_t len);
void update_ip_checksum(struct ipv4_header* ip);
void update_tcp_checksum(struct ipv4_header* ip, struct tcp_header* tcp, const uint8_t* payload, size_t payload_len);
void update_udp_checksum(struct ipv4_header* ip, struct udp_header* udp, const uint8_t* payload, size_t payload_len);

void update_ip_address(struct ipv4_header* ip, uint32_t new_src, uint32_t new_dst);
void update_tcp_ports(struct ipv4_header* ip, struct tcp_header* tcp, uint16_t new_src, uint16_t new_dst, const uint8_t* payload, size_t payload_len);
void update_udp_ports(struct ipv4_header* ip, struct udp_header* udp, uint16_t new_src, uint16_t new_dst, const uint8_t* payload, size_t payload_len);


#endif /* HELPER_H */
