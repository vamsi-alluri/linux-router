#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include "packet_helper.h"


// buffer -> raw_ethernet_frame
const struct raw_ethernet_frame* extract_ethernet_frame(const uint8_t* network_buffer) {
    return (const struct raw_ethernet_frame*)network_buffer;
}

// raw_ethernet_frame -> ethernet_header
const struct ethernet_header* extract_ethernet_header_from_frame(const struct raw_ethernet_frame* frame) {
    return &frame->header;
}

// buffer -> raw_ethernet_frame
const struct ethernet_header* extract_ethernet_header_from_buffer(const struct raw_ethernet_frame* frame) {
    return (const struct ethernet_header*)frame;
}

// ethernet payload -> IPV4 packet
const struct ipv4_packet* extract_ipv4_packet_from_eth_payload(const uint8_t* payload_from_frame) {
    return (const struct ipv4_packet*)payload_from_frame;
}

// raw ethernet frame -> IPV4 header
const struct ipv4_header* extract_ipv4_header_from_eth_frame(const uint8_t* frame) {
    return (const struct ipv4_header*)(frame + sizeof(struct ethernet_header));
}

// IPV4 packet -> IPV4 header
const struct ipv4_header* extract_ipv4_header_from_ipv4_packet(const struct ipv4_packet* packet) {
    return &packet->header;
}

// ipv4 packet -> TCP header
const struct tcp_header* extract_tcp_header_from_ipv4_packet(const struct ipv4_packet* packet){
    return (const struct tcp_header*)((uint8_t*)packet + sizeof(struct ipv4_header));
}

// raw ethernet frame -> TCP header
const struct tcp_header* extract_tcp_header_from_ethernet_frame(const uint8_t* frame) {
    const struct raw_ethernet_frame* eth_frame = extract_ethernet_frame(frame);
    const struct ipv4_packet* ip_pkt = extract_ipv4_packet_from_eth_payload(eth_frame->payload);
    return extract_tcp_header_from_ipv4_packet(ip_pkt);
}

// ipv4 packet -> UDP header
const struct udp_header* extract_udp_header_from_ipv4_packet(const struct ipv4_packet* packet){
    return (const struct udp_header*)((uint8_t*)packet + sizeof(struct ipv4_header));
}

// raw ethernet frame -> UDP header
const struct udp_header* extract_udp_header_from_ethernet_frame(const uint8_t* frame) {
    const struct raw_ethernet_frame* eth_frame = extract_ethernet_frame(frame);
    const struct ipv4_packet* ip_pkt = extract_ipv4_packet_from_eth_payload(eth_frame->payload);
    return extract_udp_header_from_ipv4_packet(ip_pkt);
}

const struct icmp_header* extract_icmp_header_from_ipv4_packet(const struct ipv4_packet* packet){
    return (const struct icmp_header*)((uint8_t*)packet + sizeof(struct ipv4_header));
}

const struct icmp_echo* extract_icmp_echo_header_from_ipv4_packet(const struct ipv4_packet* packet){
    return (const struct icmp_echo*)((uint8_t*)packet + sizeof(struct ipv4_header));
}

const struct icmp_error* extract_icmp_error_header_from_ipv4_packet(const struct ipv4_packet* packet){
    return (const struct icmp_error*)((uint8_t*)packet + sizeof(struct ipv4_header));
}

const struct arp_header* extract_arp_header_from_ethernet_frame(const uint8_t* frame) {
    return (const struct arp_header*)(frame + sizeof(struct ethernet_header));
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

uint16_t compute_tcp_checksum(struct ipv4_header* ip, struct tcp_header* tcp, const uint8_t* payload, size_t payload_len) {
    
    #pragma pack(push, 1) 
    struct {
        uint32_t src_addr;  // SRC IP ADDRESS
        uint32_t dst_addr;  // DST IP ADDRESS
        uint8_t zeros;      // 8 bits of just '0's. NOT YET DEFINED, just reserved.
        uint8_t protocol;   // TCP (6) OR UDP, apparently UDP can also use pseudo header.
        uint16_t tcp_len;   // TCP PACKET (HEADER + DATA) LENGTH
    } pseudo_header;        // ONLY used for checksum calculation and NOT used in actual packet creation.
    // Reference: https://www.baeldung.com/cs/pseudo-header-tcp#the-pseudo-header-in-tcpip
    
    #pragma pack(pop)
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

    return ~sum;
}

uint16_t compute_udp_checksum(struct ipv4_header* ip, struct udp_header* udp, const uint8_t* payload, size_t payload_len) {
    udp->check = 0;
    
    #pragma pack(push, 1)
    struct {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zeros;
        uint8_t protocol;
        uint16_t udp_len;
    } pseudo_header;
    #pragma pack(pop)

    pseudo_header.src_addr = ip->saddr;
    pseudo_header.dst_addr = ip->daddr;
    pseudo_header.zeros = 0;
    pseudo_header.protocol = IPPROTO_UDP;
    pseudo_header.udp_len = udp->len;  // Already in network byte order

    // Combine all components into a single buffer
    size_t total_len = sizeof(pseudo_header) + sizeof(struct udp_header) + payload_len;
    uint8_t *buf = malloc(total_len);
    
    memcpy(buf, &pseudo_header, sizeof(pseudo_header));
    memcpy(buf + sizeof(pseudo_header), udp, sizeof(struct udp_header));
    memcpy(buf + sizeof(pseudo_header) + sizeof(struct udp_header), payload, payload_len);

    // Compute checksum over the entire buffer
    uint16_t checksum = compute_checksum(buf, total_len);
    free(buf);
    
    return checksum;
}




