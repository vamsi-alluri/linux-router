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

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include "helper.h"

#define MAX_ENTRIES 1024
#define EXTERNAL_IP 0x0100007F  // 127.0.0.1 in network byte order
#define START_PORT 60000
#define BUFFER_SIZE 1518
#define DEFAULT_IFACE "enp0s8"
#define IPV4_ETH_TYPE 0x0800

typedef struct {
    uint32_t orig_ip;     // Original private IP
    uint16_t orig_port;   // Original port/ICMP ID
    uint32_t trans_ip;    // Translated public IP
    uint16_t trans_port;  // Translated port/ICMP ID
    uint8_t protocol;     // TCP (6), UDP (17), ICMP (1)
} nat_entry;

// Hash table structure (chaining for collisions)
typedef struct hash_node {
    nat_entry entry;
    struct hash_node* next;
} hash_node;

#define TABLE_SIZE 1024
hash_node* nat_table[TABLE_SIZE];

static nat_entry translation_table[MAX_ENTRIES];
static int raw_sock, rx_fd, tx_fd;
static uint16_t current_port = START_PORT;
static uint32_t public_ip;

uint16_t checksum(void *data, size_t len) {
    uint32_t sum = 0;
    uint16_t *ptr = data;
    
    while(len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    
    if(len) sum += *(uint8_t*)ptr;
    
    while(sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
        
    return ~sum;
}

/* NAT Entries hash table operations */
uint32_t hash(nat_entry* entry) {
    uint32_t key = entry->orig_ip ^ entry->orig_port ^ entry->protocol;
    return key % TABLE_SIZE;
}

void insert_entry(nat_entry* entry) {
    uint32_t index = hash(entry);
    hash_node* node = malloc(sizeof(hash_node));
    node->entry = *entry;
    node->next = nat_table[index];
    nat_table[index] = node;
}

nat_entry* search_entry(uint32_t orig_ip, uint16_t orig_port, uint8_t protocol) {
    // First search: exact match
    nat_entry temp = {orig_ip, orig_port, 0, 0, protocol};
    uint32_t index = hash(&temp);
    for (hash_node* node = nat_table[index]; node != NULL; node = node->next) {
        if (node->entry.orig_ip == orig_ip &&
            node->entry.orig_port == orig_port &&
            node->entry.protocol == protocol) {
            return &node->entry;
        }
    }

    // Second search: IP-only wildcard (port = 0)
    temp.orig_port = 0;
    index = hash(&temp);
    for (hash_node* node = nat_table[index]; node != NULL; node = node->next) {
        if (node->entry.orig_ip == orig_ip &&
            node->entry.protocol == protocol &&
            node->entry.orig_port == 0) {  // Wildcard port
            return &node->entry;
        }
    }

    // Third search: port-only wildcard (IP = 0)
    temp.orig_ip = 0;
    temp.orig_port = orig_port;
    index = hash(&temp);
    for (hash_node* node = nat_table[index]; node != NULL; node = node->next) {
        if (node->entry.orig_port == orig_port &&
            node->entry.protocol == protocol &&
            node->entry.orig_ip == 0) {  // Wildcard IP
            return &node->entry;
        }
    }

    return NULL;  // No match found
}

// TODO: THIS MIGHT NOT WORK, NEED TO CHECK.
// nat_entry wildcard_port = {0, 1234, 0xCB00710A, 5678, IPPROTO_TCP};
// insert_entry(&wildcard_port);

// Lookup matches any IP with port 1234:
// nat_entry* found = search_entry(192.168.1.5, 1234, IPPROTO_TCP);



void send_to_router(const char *msg) {
    write(tx_fd, msg, strlen(msg) + 1);
}


/*
What all should NAT do for each packet?
- Implement table for src ip + port, dst ip + port, src mac and dst mac.
- Decide how to assign ports for outgoing packets.
- Track TCP connections, TCP SYN, TCP FIN, TCP FIN ACK.
- Get DHCP Table and store it in memory.
- Implement memory clean up once in every TODO.

*/
void handle_packet(unsigned char *buffer, ssize_t len) {

    // Get ethernet frame and header.
    struct raw_ethernet_frame *eth_frame = extract_ethernet_frame(buffer);
    struct ethernet_header *eth_header = &eth_frame->header;
    
    if(ntohs(eth_header->type) != IPV4_ETH_TYPE) return;  // Anything other than IPv4 SHALL NOT PASS!
    
    // Get IP packet and header.
    struct ipv4_packet *ip_packet = extract_ipv4_packet_from_eth_payload(&eth_frame->payload);
    struct ipv4_header *ip_header = extract_ipv4_header_from_ipv4_packet(ip_packet);

    if(&ip_header->version != 4) return;                   // Anything other than IPv4 SHALL NOT PASS!

    switch (&ip_header->protocol){
        case 1:
        // ICMP
            break;
        case 2:
        // IGMP
            break;
        case 6:
        // TCP
            break;
        case 17:
        // UDP
            break;
        case 89:
        // OSPF
            break;
        default:
        // Unsupported protocol
            return;
    }

    uint8_t *transport = extract_tcp(ip);
    uint16_t sport, dport;
    uint8_t proto = ip->protocol;

    if(proto == 6) {  // TCP
        tcp_header *tcp = (tcp_header*)transport;
        sport = ntohs(tcp->sport);
        dport = ntohs(tcp->dport);
    } else if(proto == 17) {  // UDP
        udp_header *udp = (udp_header*)transport;
        sport = ntohs(udp->sport);
        dport = ntohs(udp->dport);
    } else return;

    // Find or create NAT entry
    nat_entry *entry = NULL;
    for(int i = 0; i < MAX_ENTRIES; i++) {
        if(translation_table[i].internal_ip == ip->saddr && 
           translation_table[i].internal_port == sport) {
            entry = &translation_table[i];
            break;
        }
    }

    if(!entry) {
        entry = &translation_table[current_port % MAX_ENTRIES];
        entry->internal_ip = ip->saddr;
        entry->internal_port = sport;
        entry->external_port = current_port++;
        
        char msg[64];
        snprintf(msg, sizeof(msg), "NAT: New mapping %u -> %hu\n", 
                ntohl(ip->saddr), entry->external_port);
        send_to_router(msg);
    }

    // Modify packet
    uint32_t orig_saddr = ip->saddr;
    ip->saddr = htonl(EXTERNAL_IP);
    
    if(proto == 6) {
        tcp_header *tcp = (tcp_header*)transport;
        tcp->sport = htons(entry->external_port);
        tcp->check = 0;
        tcp->check = checksum(tcp, sizeof(tcp_header));
    } else if(proto == 17) {
        udp_header *udp = (udp_header*)transport;
        udp->sport = htons(entry->external_port);
        udp->check = 0;
    }

    ip->check = 0;
    ip->check = checksum(ip, sizeof(ipv4_header));
    
    send(raw_sock, buffer, len, 0);
    ip->saddr = orig_saddr;  // Restore for state tracking
}

void nat_main(int router_rx, int router_tx) {
    rx_fd = router_rx;
    tx_fd = router_tx;
    
    struct sockaddr_ll saddr;
    struct ifreq ifr;
    unsigned char buffer[BUFFER_SIZE];
    
    // Socket setup
    if((raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        send_to_router("NAT: Socket creation failed\n");
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, "enp0s8", IFNAMSIZ);
    if(ioctl(raw_sock, SIOCGIFINDEX, &ifr) < 0) {
        send_to_router("NAT: Interface config failed\n");
        close(raw_sock);
        exit(EXIT_FAILURE);
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_ifindex = ifr.ifr_ifindex;
    saddr.sll_protocol = htons(ETH_P_ALL);
    
    if(bind(raw_sock, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        send_to_router("NAT: Bind failed\n");
        close(raw_sock);
        exit(EXIT_FAILURE);
    }

    // Promiscuous mode
    if(ioctl(raw_sock, SIOCGIFFLAGS, &ifr) != -1) {
        ifr.ifr_flags |= IFF_PROMISC;
        ioctl(raw_sock, SIOCSIFFLAGS, &ifr);
    }

    send_to_router("NAT: Ready\n");

    fd_set read_fds;
    while(1) {
        FD_ZERO(&read_fds);
        FD_SET(raw_sock, &read_fds);
        FD_SET(rx_fd, &read_fds);

        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        int ready = select(FD_SETSIZE, &read_fds, NULL, NULL, &tv);
        
        if(ready < 0) {
            send_to_router("NAT: Select error\n");
            break;
        }

        if(FD_ISSET(rx_fd, &read_fds)) {
            char cmd[256];
            if(read(rx_fd, cmd, sizeof(cmd)) <= 0 || strcmp(cmd, "shutdown") == 0) {
                send_to_router("NAT: Shutting down\n");
                break;
            }
        }

        if(FD_ISSET(raw_sock, &read_fds)) {
            ssize_t len = recv(raw_sock, buffer, BUFFER_SIZE, 0);
            if(len > 0) handle_packet(buffer, len);
        }
    }

    close(raw_sock);
    close(rx_fd);
    close(tx_fd);
    exit(EXIT_SUCCESS);
}
