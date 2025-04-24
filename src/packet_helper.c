#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <string.h>
#include "packet_helper.h"


// Transforms raw data to eth frame.
const struct raw_ethernet_frame* extract_ethernet_frame(const uint8_t* network_buffer) {
    return (const struct raw_ethernet_frame*)network_buffer;
}

// Extracts eth header from eth frame.
const struct ethernet_header* extract_ethernet_header_from_frame(const struct raw_ethernet_frame* frame) {
    return &frame->header;
}

// Extracts eth header from raw data.
const struct ethernet_header* extract_ethernet_header_from_buffer(const struct raw_ethernet_frame* frame) {
    return (const struct ethernet_header*)frame;
}

// raw ethernet frame -> IPV4 packet
const struct ipv4_packet* extract_ipv4_packet_from_eth_frame(const uint8_t* raw_ethernet_frame) {
    const struct raw_ethernet_frame* frame = extract_ethernet_frame(raw_ethernet_frame);
    return (const struct ipv4_packet*)frame->payload;
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


