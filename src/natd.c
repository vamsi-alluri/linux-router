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

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <time.h>
#include "packet_helper.h"


#define BUFFER_SIZE 1518        // To cover the whole ethernet frame.
#define MAX_ENTRIES 1024
#define EXTERNAL_IP 0x0100007F  // 127.0.0.1 in network byte order
#define START_PORT 60000
#define DEFAULT_LAN_IFACE "enp0s8"  // This has to be configurable.
#define DEFAULT_WAN_IFACE "enp0s3"  // This has to be configurable.
#define TABLE_SIZE 1024
#define DEFAULT_LOG_PATH "/home/osboxes/cs536/router/nat_log.txt"

#define TCP_IP_TYPE 6
#define UDP_IP_TYPE 17
#define ICMP_IP_TYPE 1
#define IPV4_ETH_TYPE 0x0800

// NAT table:
struct nat_entry{
    uint32_t orig_ip;           // LAN IP
    uint16_t orig_port;         // LAN port/ICMP ID
    uint32_t trans_ip;          // Translated WAN IP
    uint16_t trans_port;        // Translated WAN port/ICMP ID
    uint8_t protocol;           // TCP (6), UDP (17), ICMP (1)
};

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


/// Utility Functions:

// Sends binary content to router.
void send_to_router(unsigned char *msg, int msg_len) {
    write(tx_fd, msg, msg_len);
}

void append_ln_to_log_file(const char *msg) {
    // Clean up the log file if the size is more than 10 MB.
    
    FILE *log_file = fopen(log_file_path, "r");
    if (log_file) {
        fseek(log_file, 0, SEEK_END);
        long file_size = ftell(log_file);
        fclose(log_file);
        
        if (file_size > 10 * 1024 * 1024) { // 10 MB
            log_file = fopen(log_file_path, "w");
            if (log_file) {
                fprintf(log_file, "\n\n");
                fclose(log_file);
            }
        }
    }
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char buffer[26];
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    log_file = fopen(log_file_path, "a");
    if (log_file) {
        fprintf(log_file, "[%s] %s\n", buffer, msg);
        fclose(log_file);
    }
}

// Should be only called once at the start of the program.
void init_log_file() {
    FILE *log_file = fopen("nat_log.txt", "w");
    if (log_file) {
        fprintf(log_file, "\n\n");
        fprintf(log_file, "NAPT service started at ");
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char buffer[26];
        strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
        fprintf(log_file, "%s\n", buffer);
        fclose(log_file);
    }
}

// Using the config files above load the configurations into the NAT table.
// This should be called once at the start of the program.
void load_configurations() {
    // Load NAT configurations from files.
    // This function should read the configuration files and populate the NAT table.
    // For now, we will just print a message.
    append_ln_to_log_file("NAT: Loading configurations...\n");
    
    // Example of loading a static mapping:
    // nat_static_mapping mapping = {0x0100007F, 1234, 0x0100007F, 5678, IPPROTO_TCP};
    append_ln_to_log_file("NAT: Loaded static mapping.");
}








/// Actual stuff:

void handle_packet(unsigned char *buffer, ssize_t len) {

    // Get ethernet frame and header.
    struct raw_ethernet_frame *eth_frame = extract_ethernet_frame(buffer);
    struct ethernet_header *eth_header = &eth_frame->header;
    
    if(ntohs(eth_header->type) != IPV4_ETH_TYPE) return;  // Anything other than IPv4 SHALL NOT PASS!
    
    // Get IP packet and header.
    struct ipv4_packet *ip_packet = extract_ipv4_packet_from_eth_payload(&eth_frame->payload);
    struct ipv4_header *ip_header = extract_ipv4_header_from_ipv4_packet(ip_packet);

    if(ip_header->version != 4) return;                   // Anything other than IPv4 SHALL NOT PASS!

    // Copy src address and dsr address.
    uint16_t sport, dport;
    uint32_t src_ip = ip_header->saddr;
    uint32_t dst_ip = ip_header->daddr;

    struct nat_entry packet_details;

    packet_details.orig_ip = src_ip;
    packet_details.orig_port = sport;

    switch (ip_header->protocol){
        case ICMP_IP_TYPE:
            // Handle ICMP packet.
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

    // Update NAT table with the current data, if not already present. Mainly if it's an outbound packet.
}

int init_socket(char *iface_name){
    
    struct sockaddr_ll saddr;
    struct ifreq ifr;
    int raw_sock;

    if((raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        append_ln_to_log_file("NAT: Socket creation failed\n");

        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
    if(ioctl(raw_sock, SIOCGIFINDEX, &ifr) < 0) {
        append_ln_to_log_file("NAT: Interface config failed\n");
        close(raw_sock);
        exit(EXIT_FAILURE);
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_ifindex = ifr.ifr_ifindex;
    saddr.sll_protocol = htons(ETH_P_ALL);
    
    if(bind(raw_sock, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        append_ln_to_log_file("NAT: Bind failed\n");
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


void nat_main(int router_rx, int router_tx) {
    rx_fd = router_rx;
    tx_fd = router_tx;
    
    unsigned char buffer[BUFFER_SIZE];

    // Send the PID to router process for "killing" purposes.
    pid_t pid = getpid();
    send_to_router(&pid, sizeof(pid_t));
    
    // Socket setup

    lan_raw = init_socket(DEFAULT_LAN_IFACE);
    wan_raw = init_socket(DEFAULT_WAN_IFACE);
    
    init_log_file();
    append_ln_to_log_file("NAT: Ready\n");

    fd_set read_fds;
    while(1) {
        FD_ZERO(&read_fds);
        FD_SET(lan_raw, &read_fds);
        FD_SET(wan_raw, &read_fds);
        FD_SET(rx_fd, &read_fds);

        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        int ready = select(FD_SETSIZE, &read_fds, NULL, NULL, &tv);
        
        if(ready < 0) {
            append_ln_to_log_file("NAT: Select error\n");
            break;
        }

        if(FD_ISSET(rx_fd, &read_fds)) {
            char cmd[256];
            if(read(rx_fd, cmd, sizeof(cmd)) <= 0 || strcmp(cmd, "shutdown") == 0) {
                append_ln_to_log_file("NAT: Shutting down\n");  // Add a timestamp - UTC.
                break;
            }
        }

        if(FD_ISSET(lan_raw, &read_fds)) {
            ssize_t len = recv(lan_raw, buffer, BUFFER_SIZE, 0);
            if(len > 0) handle_packet(buffer, len);
        }
    }

    close(lan_raw);
    close(wan_raw);
    close(rx_fd);
    close(tx_fd);
    exit(EXIT_SUCCESS);
}
