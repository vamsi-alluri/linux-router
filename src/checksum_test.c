#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include "packet_helper.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

void process_packet(unsigned char *buffer, int size) {
    // Extract Ethernet frame using helper
    const struct raw_ethernet_frame *eth_frame = extract_ethernet_frame(buffer);
    const struct ethernet_header *eth_hdr = extract_ethernet_header_from_frame(eth_frame);

    if (ntohs(eth_hdr->type) != ETH_P_IP) return;

    // Extract IP packet using helper
    const struct ipv4_packet *ip_pkt = extract_ipv4_packet_from_eth_payload(eth_frame->payload);
    const struct ipv4_header *ip_hdr = &ip_pkt->header;

    if (ip_hdr->version != 4 || ip_hdr->ihl < 5) return;
    if (ip_hdr->protocol != IPPROTO_UDP) return;

    // Extract UDP header using helper
    const struct udp_header *udp_hdr = extract_udp_header_from_ipv4_packet(ip_pkt);
    
    // Calculate payload parameters using helper-derived pointers
    uint16_t udp_len = ntohs(udp_hdr->len);
    size_t payload_len = udp_len - sizeof(struct udp_header);
    
    // Get payload pointer using header structure offsets
    const uint8_t *payload = (const uint8_t *)udp_hdr + sizeof(struct udp_header);
    
    // Validate payload access
    const uint8_t *packet_end = buffer + size;
    if ((payload + payload_len) > packet_end) return;

    // Calculate checksum
    uint16_t received_checksum = udp_hdr->check;
    struct udp_header *modifiable_udp = (struct udp_header *)udp_hdr;
    modifiable_udp->check = 0;
    
    uint16_t calculated_checksum = compute_udp_checksum(
        (struct ipv4_header *)ip_hdr, 
        modifiable_udp, 
        payload, 
        payload_len
    );

    printf("UDP checksum - custom headers: received=0x%04x, calculated=0x%04x [%s]\n",
           ntohs(received_checksum), ntohs(calculated_checksum),
           (received_checksum == calculated_checksum || received_checksum == 0) ? "OK" : "BAD");
}


unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    for (; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/* UDP checksum calculation using standard headers */
uint16_t udp_checksum(const struct iphdr *iph, const struct udphdr *udph, const uint8_t *payload, size_t payload_len) {
    struct {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_len;
    } pseudo_header;

    pseudo_header.src_addr = iph->saddr;
    pseudo_header.dst_addr = iph->daddr;
    pseudo_header.zero = 0;
    pseudo_header.protocol = IPPROTO_UDP;
    pseudo_header.udp_len = udph->len;

    size_t udp_len = ntohs(udph->len);
    size_t psize = sizeof(pseudo_header) + udp_len;
    uint8_t *buf = malloc(psize);
    memcpy(buf, &pseudo_header, sizeof(pseudo_header));
    memcpy(buf + sizeof(pseudo_header), udph, sizeof(struct udphdr));
    memcpy(buf + sizeof(pseudo_header) + sizeof(struct udphdr), payload, udp_len - sizeof(struct udphdr));

    uint16_t result = csum((unsigned short *)buf, (psize + 1) / 2);
    free(buf);
    return result;
}

void process_packet_libraries(unsigned char *buffer, int size) {
    // Ethernet header
    struct ethhdr *eth = (struct ethhdr *)buffer;
    if (ntohs(eth->h_proto) != ETH_P_IP) return;

    // IP header
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    if (iph->protocol != IPPROTO_UDP) return;

    // UDP header
    size_t iphdr_len = iph->ihl * 4;
    struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + iphdr_len);

    // Payload
    uint8_t *payload = buffer + sizeof(struct ethhdr) + iphdr_len + sizeof(struct udphdr);
    size_t payload_len = ntohs(udph->len) - sizeof(struct udphdr);

    // Checksum calculation
    uint16_t received = udph->check;
    udph->check = 0;
    uint16_t calculated = udp_checksum(iph, udph, payload, payload_len);

     printf("UDP checksum - libraries: received=0x%04x, calculated=0x%04x [%s]\n",
           ntohs(received), ntohs(calculated),
           (received == calculated || received == 0) ? "OK" : "BAD");
    udph->check = received;
}




int main() {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // Bind to interface
    struct sockaddr_ll saddr = {0};
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = if_nametoindex("eth0");
    
    if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    printf("Listening for UDP packets using packet_helper...\n");
    unsigned char buffer[ETH_FRAME_LEN];
    
    while (1) {
        ssize_t data_size = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (data_size < 0) {
            perror("recvfrom");
            break;
        }
        process_packet_libraries(buffer, data_size);
        process_packet(buffer, data_size);
    }

    close(sockfd);
    return 0;
}
