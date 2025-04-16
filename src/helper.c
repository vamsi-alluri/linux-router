#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <string.h>
#include "helper.h"

struct eth_header* extract_ethernet(const uint8_t* frame) {
    return (struct eth_header*)frame;
}

struct ipv4_header* extract_ipv4(const uint8_t* frame) {
    return (struct ipv4_header*)(frame + sizeof(struct eth_header));
}

struct tcp_header* extract_tcp(const uint8_t* frame) {
    struct ipv4_header* ip = extract_ipv4(frame);
    return (struct tcp_header*)((uint8_t*)ip + (ip->ihl * 4));
}

struct udp_header* extract_udp(const uint8_t* frame) {
    struct ipv4_header* ip = extract_ipv4(frame);
    return (struct udp_header*)((uint8_t*)ip + (ip->ihl * 4));
}


void reassemble_ethernet(uint8_t* frame, const struct eth_header* eth, 
                            const struct ipv4_header* ip,const void* transport_header, 
                            const uint8_t* payload, size_t payload_len) 
{
    memcpy(frame, eth, sizeof(struct eth_header));
    uint8_t* ip_start = frame + sizeof(struct eth_header);
    memcpy(ip_start, ip, ip->ihl * 4);

    uint8_t* transport_start = ip_start + (ip->ihl * 4);
    size_t transport_len;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcp_header* tcp = (struct tcp_header*)transport_header;
        transport_len = tcp->doff * 4;
    } 
    else if (ip->protocol == IPPROTO_UDP) {
        transport_len = sizeof(struct udp_header);
    } 
    else    // Handle other protocols or error cases
        return;

    memcpy(transport_start, transport_header, transport_len);
    memcpy(transport_start + transport_len, payload, payload_len);
}


uint16_t compute_checksum(const void* data, size_t len) {
    const uint16_t* buf = data;
    uint32_t sum = 0;
    
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    if (len > 0) {
        sum += *(uint8_t*)buf;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    
    return ~sum;
}

void update_ip_checksum(struct ipv4_header* ip) {
    ip->check = 0;
    ip->check = compute_checksum(ip, ip->ihl * 4);
}

void update_tcp_checksum(struct ipv4_header* ip, struct tcp_header* tcp, const uint8_t* payload, size_t payload_len) {
    tcp->check = 0;
    
    struct {
        uint32_t src_addr;  // SRC IP ADDRESS
        uint32_t dst_addr;  // DST IP ADDRESS
        uint8_t zeros;      // 8 bits of just '0's. NOT YET DEFINED, just reserved.
        uint8_t protocol;   // TCP (6) OR UDP, apparently UDP can also use pseudo header.
        uint16_t tcp_len;   // TCP PACKET (HEADER + DATA) LENGTH
    } pseudo_header;        // ONLY used for checksum calculation and NOT used in actual packet creation.
    // Reference: https://www.baeldung.com/cs/pseudo-header-tcp#the-pseudo-header-in-tcpip

    pseudo_header.src_addr = ip->saddr;
    pseudo_header.dst_addr = ip->daddr;
    pseudo_header.zeros = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_len = htons(ntohs(ip->tot_len) - (ip->ihl * 4));

    // Calculate checksum over pseudo-header
    uint32_t sum = compute_checksum(&pseudo_header, sizeof(pseudo_header));

    // Add the TCP header and payload
    sum += compute_checksum(tcp, tcp->doff * 4);
    sum += compute_checksum(payload, payload_len);

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    tcp->check = ~sum;
}

void update_udp_checksum(struct ipv4_header* ip, struct udp_header* udp, const uint8_t* payload, size_t payload_len) {
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

    // Calculate checksum over pseudo-header
    uint32_t sum = compute_checksum(&pseudo_header, sizeof(pseudo_header));

    // Add the UDP header and payload
    sum += compute_checksum(udp, sizeof(struct udp_header));
    sum += compute_checksum(payload, payload_len);

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    udp->check = ~sum;
}



void update_ip_address(struct ipv4_header* ip, uint32_t new_src, uint32_t new_dst) {
    ip->saddr = new_src;
    ip->daddr = new_dst;
    update_ip_checksum(ip);
}

void update_tcp_ports(struct ipv4_header* ip, struct tcp_header* tcp, uint16_t new_src, uint16_t new_dst, const uint8_t* payload, size_t payload_len) {
    tcp->sport = htons(new_src);
    tcp->dport = htons(new_dst);
    update_tcp_checksum(ip, tcp, payload, payload_len);
}

void update_udp_ports(struct ipv4_header* ip, struct udp_header* udp, uint16_t new_src, uint16_t new_dst, const uint8_t* payload, size_t payload_len) {
    udp->sport = htons(new_src);
    udp->dport = htons(new_dst);
    update_udp_checksum(ip, udp, payload, payload_len);
}


