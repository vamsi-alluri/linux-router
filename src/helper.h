#ifndef HELPER_H
#define HELPER_H

struct eth_header;
struct ipv4_header;
struct tcp_header;
struct udp_header;

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
