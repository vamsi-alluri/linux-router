#include "dnsd.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#define DNS_PORT 53        // Well-known port
#define LOOKUP_PORT 30000        // Arbitrary unused port & ignored by NAT
#define LOOKUP_IP 0x08080808     // Google DNS IPv4
#define BUFFER_SIZE 500

void dns_main(int rx_fd, int tx_fd){
    // Send the PID back to the parent for processing
    pid_t pid = getpid();
    write(tx_fd, &pid, sizeof(pid_t)); // Send the pid to be stored by the parent process. 

    memset(domain_table, 0, MAX_ENTRIES * sizeof(dns_bucket *));   // Clear domain_table

    // Add a dummy value to the table at 0 that will be used for iterating through it
    domain_table[0] = malloc(sizeof(dns_bucket));
    memset(&domain_table[0]->entry, 0, sizeof(dns_entry));
    domain_table[0]->entry.ttl = LONG_MAX;
    domain_table[0]->next = domain_table[0];

    struct sockaddr_in ser_addr, cli_addr;
    int flags, s, slen = sizeof(cli_addr), recv_len, send_len, select_ret;

    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("socket");
        return -1;
    }

    struct ifreq myreq;
    memset(&myreq, 0, sizeof(myreq));
    strncpy(myreq.ifr_name, "enp0s8", IFNAMSIZ);
    
    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, (void *)&myreq, sizeof(myreq)) < 0) {
        perror("setsockopt");
        close(s);
        return -1;
    }

    if (flags = fcntl(s, F_GETFL) < 0) {
        perror("F_GETFL");
        close(s);
        return -1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(s, F_SETFL, flags) < 0) {
        perror("F_SETFL");
        close(s);
        return -1;
    }

    memset((char *)&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_port = htons(DNS_PORT);
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *)&ser_addr, sizeof(ser_addr)) < 0) {
        perror("bind");
        close(s);
        return -1;
    }

    // system("clear");
    printf("...This is DNS server (Non-Blocking Version) listening on port %d...\n\n", DNS_PORT);

    struct timeval tv = {5, 0}; // 5 seconds, 0 microseconds
    fd_set rfds;
    while (true) {
        FD_ZERO(&rfds);
        FD_SET(s, &rfds);
        if (select_ret = select(s + 1, &rfds, NULL, NULL, &tv) < 0) {
            perror("select");
            continue;
        }
        else if (select_ret == 0) continue; // Timeout

        // FD_ISSET(s, &rfds) is true here

        unsigned char buffer[BUFFER_SIZE];
        memset(buffer, '\0', BUFFER_SIZE);

        if ((recv_len = recvfrom(s, buffer, BUFFER_SIZE, 0,
                                    (struct sockaddr *)&cli_addr, &slen)) < 0) {
            perror("recvfrom");
            continue;
        }

        printf("Received packet from %s, port number:%d\n",
                inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

        dns_hdr hdr;
        int offset = process_packet(&hdr, buffer);
        if (offset < 0) continue;      // IDK bc it fails somehow prob just abandon this request

        // memset(&hdr, 0, sizeof(hdr));
        
        // // Format for DNS header
        // hdr.id = ntohs(*(unsigned short*)buffer);
        // unsigned short flags = ntohs(*(unsigned short*)(buffer + 2));
        // hdr.qr = (flags >> 15) & 0x1;
        // hdr.op = (flags >> 11) & 0xf;
        // hdr.aa = (flags >> 10) & 0x1;
        // hdr.tc = (flags >> 9) & 0x1;
        // hdr.rd = (flags >> 8) & 0x1;
        // hdr.ra = (flags >> 7) & 0x1;
        // hdr.z = (flags >> 6) & 0x1;
        // hdr.ad = (flags >> 5) & 0x1;
        // hdr.cd = (flags >> 4) & 0x1;
        // hdr.rcd = flags & 0xf;
        // hdr.numQ = ntohs(*(unsigned short*)(buffer + 4));
        // hdr.numA = ntohs(*(unsigned short*)(buffer + 6));
        // hdr.auRR = ntohs(*(unsigned short*)(buffer + 8));
        // hdr.adRR = ntohs(*(unsigned short*)(buffer + 10));

        // /* Process the data of DNS starting at buffer + sizeof(dns_hdr) */

        


        // // int offset = lookup_domains(buffer, &hdr);
        
        // hdr.auRR = 0;   // Not implemented
        // hdr.adRR = 0;   // Not implemented

        // unsigned short offset = sizeof(dns_hdr);

        // // For every requested domain name
        // for (int i = 0; i < hdr.numQ; i++) {
        //     dns_entry map;

        //     // Parses the ith domain in the request and stores in map.domain
        //     // Leaves buffer untouched and offset will point to next byte to be read
        //     offset = process_domain(offset, buffer, map.domain, 0);

        //     unsigned short type = ntohs(*(unsigned short*)(buffer + offset));
        //     if (type != 0x0001) {      /* All types but A (IPv4) Not Implemented */
        //         hdr.rcd = 4;
        //         // return offset + 4; // TODO: For now, idk how to end ill bounce back to client somehow
        //     }

        //     unsigned short class = ntohs(*(unsigned short*)(buffer + offset + 2));
        //     if (class != 0x0001) {      /* All classes but IN (Internet Class) Not Implemented */
        //         hdr.rcd = 4;
        //         // return offset + 4; // TODO: For now, idk if right value bc ending early
        //     }
        //     offset += 4;

        //     // Looks up the ith domain stored in map.domain and stores the dns_entry in map
        //     // Will either retreive from table or retrieve upstream
        //     if (get_domain(&map, offset, buffer) < 0) {
        //         continue; // IDK bc it fails somehow prob just abandon this request
        //     }

        //     // TODO: Contruct answers here and store somewhere ill have to process all questions before putting at end of the buffer
        //     // After that we can do the next question

        // }

        hdr.ra = 1;     // Think need TODO

                                                              // id same
        flags = 0;                                            // Clear current flags
        flags |= (hdr.qr & 0x1) << 15;                        // reply = 1
        flags |= (hdr.op & 0xf) << 11;
        flags |= (hdr.aa & 0x1) << 10;
        flags |= (hdr.tc & 0x1) << 9;
        flags |= (hdr.rd & 0x1) << 8;                        // TODO: might need these for the compression ptrs
        flags |= (hdr.ra & 0x1) << 7;                        // 
        flags |= (hdr.z & 0x1) << 6;
        flags |= (hdr.ad & 0x1) << 5;
        flags |= (hdr.cd & 0x1) << 4;
        flags |= hdr.rcd & 0xf;                               // Maybe Replace with the Not implemented hdr.rcd of 4
        *(unsigned short*)(buffer + 2) = htons(flags);
                                                              // numQ same
        *(unsigned short*)(buffer + 6) = htons(hdr.numA);     // numA updates
        *(unsigned short*)(buffer + 8) = htons(hdr.auRR);     // Not implemented (hdr.auRR = 0)
        *(unsigned short*)(buffer + 10) = htons(hdr.adRR);    // Not implemented (hdr.adRR = 0)


        if ((send_len = sendto(s, buffer, offset, 0,
                                    (struct sockaddr *)&cli_addr, &slen)) < 0) {
            perror("sendto");
            continue;
        }

        // Send back packet if not implemented
        if (hdr.rcd == 4) {

            // Packet is identical to as it was received but with the Not implemented flag triggered.
            printf("Sent packet with not implemented type or class back to %s, port number:%d\n",
                    inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
        }
        // If implemented, send back an actual response
        else {
            printf("Sent packet back to %s, port number:%d\n",
                    inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
        }


        // char *domain_name = get_domain(offset, buffer, map.ip);
        // if (domain_name[0] == '\0') {

        // }


        /* Set the data of DNS response header */


        // unsigned char response[BUFFER_SIZE];
        // memset(response, '\0', BUFFER_SIZE);

        // // Format for DNS response
        // *(unsigned short*)(response + 0) = htons(hdr.id);
        // flags = 0;
        // flags |= (hdr.qr & 0x1) << 15;
        // flags |= (hdr.op & 0xf) << 11;
        // flags |= (hdr.aa & 0x1) << 10;
        // flags |= (hdr.tc & 0x1) << 9;
        // flags |= (hdr.rd & 0x1) << 8;
        // flags |= (hdr.ra & 0x1) << 7;
        // flags |= (hdr.z & 0x1) << 6;
        // flags |= (hdr.ad & 0x1) << 5;
        // flags |= (hdr.cd & 0x1) << 4;
        // flags |= hdr.rcd & 0xf;
        // *(unsigned short*)(response + 2) = htons(flags);
        // *(unsigned short*)(response + 4) = htons(hdr.numQ);
        // *(unsigned short*)(response + 6) = htons(hdr.numA);
        // *(unsigned short*)(response + 8) = htons(hdr.auRR);
        // *(unsigned short*)(response + 10) = htons(hdr.adRR);



        /* Set the data of DNS starting at response + sizeof(dns_hdr) */


    }
    close(s);
    return 0;
}

int process_domain(unsigned short offset, char *buffer, char *domain, int index) {
    while (true) {
        // Is a pointer iff first 2 bits are 1s
        if ((buffer[offset] & 0xC0) == 0xC0) {
            // Convert to host byte order then flip first 2 bits to 0s
            unsigned short ptr = ntohs(*(unsigned short *)(buffer + offset)) & 0x3FFF;
            
            // Now ptr contains the offset within the DNS packet that we want to continue reading from.
            // So we will replace offset with ptr in a recursive call.
            process_domain(ptr, buffer, domain, index);
            // Return so offset is pointing to next byte to be read after ptr offset
            return offset + 2;
        }
        // Not a pointer (Labels are at most 63 octets so must begin with 2 0 bits)
        int i = 0;
        while (i < buffer[offset]) {
            domain[index++] = buffer[offset + ++i];
        }
        offset += ++i;
        if (buffer[offset] == '\0') break;
        domain[index++] = '.';
    }
    domain[index] = '\0';
    // Return so offset is pointing to next byte to be read after '\0'
    return offset + 1;
}

// using the djb2 hashing function
unsigned long get_hash(unsigned char *domain) {
    unsigned long hash = 5381;
    int c;
    for (int i = 0; c = *(domain + i); ++i)
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    return hash % MAX_ENTRIES;
}

// This must ONLY be used if the domain name does not have an entry currently
unsigned long insert_table(unsigned char *domain, unsigned char **ip, int numIp) {
    unsigned long index = get_hash(domain);
    while (domain_table[index]) index++;     // Linear probing
    
    domain_table[index] = malloc(sizeof(dns_bucket));
    memset(&domain_table[index]->entry, 0, sizeof(dns_entry));
    strncpy(domain_table[index]->entry.domain, domain, strlen(domain));
    domain_table[index]->entry.numIp = numIp;
    for (int i = 0; i < numIp; ++i) strncpy(domain_table[index]->entry.ip[i], ip[i], IP_LENGTH);
    domain_table[index]->entry.ttl = time(NULL) + DEFAULT_TTL;
    domain_table[index]->next = domain_table[0]->next;
    domain_table[0]->next = domain_table[index];
    return index;
}

void clean_table() {
    dns_bucket *start = domain_table[0];
    dns_bucket *prev = start;
    dns_bucket *curr = prev->next;
    while (start != curr) {
        if (curr->entry.ttl < time(NULL)) {

            // This entry is expired and will be removed from the table
            prev->next = curr->next;
            free(curr);
        }
        else {
            prev = curr;
        }
        curr = prev->next;
    }
}

int get_domain(dns_entry *map, int offset, char *buffer) {
    unsigned long index = get_hash(map->domain);
    while (domain_table[index]) {
        if ((strlen(domain_table[index]->entry.domain) == strlen(map->domain)) &&
            (strncmp(map->domain, domain_table[index]->entry.domain, strlen(map->domain)) == 0)) {
            
            // We found the Domain Name in the table so...
            // Refresh ttl
            // TODO: should i do this? domain_table[index]->entry.ttl = time(NULL) + DEFAULT_TTL;
            // Copy its entry and return
            memcpy(map, &domain_table[index]->entry, sizeof(dns_entry));
            return 0;
        }
        index++;
    }
    
    // If we reach this point we need to query upstream for the IP addresses
    printf("Not found in table... Now sending upstream...\n");


    // Here is the socket setup for sending/receiving DNS queries to/from the internet

    int sock;
    struct sockaddr_in sock_addr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("socket-upstream");
        return -1;
    }

    // Might not need because it might be default, but will leave for now to be safe
    struct ifreq myreqInt;
    memset(&myreqInt, 0, sizeof(myreqInt));
    strncpy(myreqInt.ifr_name, "enp0s3", IFNAMSIZ);
    
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void *)&myreqInt, sizeof(myreqInt)) < 0) {
        perror("setsockopt-upstream");
        close(sock);
        return -1;
    }

    memset((char *)&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(DNS_PORT);
    sock_addr.sin_addr.s_addr = htonl(LOOKUP_IP);

    if (bind(sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0) {
        perror("bind-upstream");
        close(sock);
        return -1;
    }

    // Setup Ends here



    int send_len, recv_len, slen = sizeof(sock_addr);
    if ((send_len = sendto(sock, buffer, offset, 0,
       (struct sockaddr*)&sock_addr, sizeof(sock_addr))) < 0) {
        perror("sendto-upstream");
        return -1;
    }
    printf("Sent packet to upstream %s, port number:%d\n",
            inet_ntoa(sock_addr.sin_addr), ntohs(sock_addr.sin_port));

    // TODO: in case idk u can uncomment
    // memset(buffer, 0, offset);

    if ((recv_len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                (struct sockaddr *)&sock_addr, &slen)) < 0) {
        perror("recvfrom-upstream");
        return -1;
    }

    printf("Received packet from upstream %s, port number:%d\n",
            inet_ntoa(sock_addr.sin_addr), ntohs(sock_addr.sin_port));
    
    // TODO: process packet to get the domain and array of ips

    dns_hdr hdr;
    memset(&hdr, 0, sizeof(dns_hdr));
    
    // Format for DNS header
    hdr.id = ntohs(*(unsigned short*)buffer);
    unsigned short flags = ntohs(*(unsigned short*)(buffer + 2));
    hdr.qr = (flags >> 15) & 0x1;
    hdr.op = (flags >> 11) & 0xf;
    hdr.aa = (flags >> 10) & 0x1;
    hdr.tc = (flags >> 9) & 0x1;
    hdr.rd = (flags >> 8) & 0x1;
    hdr.ra = (flags >> 7) & 0x1;
    hdr.z = (flags >> 6) & 0x1;
    hdr.ad = (flags >> 5) & 0x1;
    hdr.cd = (flags >> 4) & 0x1;
    hdr.rcd = flags & 0xf;
    hdr.numQ = ntohs(*(unsigned short*)(buffer + 4));
    hdr.numA = ntohs(*(unsigned short*)(buffer + 6));
    hdr.auRR = ntohs(*(unsigned short*)(buffer + 8));
    hdr.adRR = ntohs(*(unsigned short*)(buffer + 10));

    if (hdr.qr != 1) {
        perror("not response upstream");
        return -1; 
    }

    if (hdr.rcd == 4) {
        perror("not implemented upstream");
        return -1; 
    }

    // buffer[offset] should be the first byte of answers
    for (int k = 0; k < hdr.numA; k++) {
        for (int l = 0; l < IP_LENGTH; l++) {
            map->ip[k][l] = buffer[offset + 12 + (k * ANS_LENGTH) + l];
        }
    }
    
    // end TODO 
    

    index = insert_table(map->domain, map->ip, hdr.numA);
    memcpy(map, &domain_table[index]->entry, sizeof(dns_entry));
    return 0;
}

int process_packet(dns_hdr *hdr, char *buffer) {
    memset(hdr, 0, sizeof(dns_hdr));
    
    // Format for DNS header
    hdr->id = ntohs(*(unsigned short*)buffer);
    unsigned short flags = ntohs(*(unsigned short*)(buffer + 2));
    hdr->qr = (flags >> 15) & 0x1;
    hdr->op = (flags >> 11) & 0xf;
    hdr->aa = (flags >> 10) & 0x1;
    hdr->tc = (flags >> 9) & 0x1;
    hdr->rd = (flags >> 8) & 0x1;
    hdr->ra = (flags >> 7) & 0x1;
    hdr->z = (flags >> 6) & 0x1;
    hdr->ad = (flags >> 5) & 0x1;
    hdr->cd = (flags >> 4) & 0x1;
    hdr->rcd = flags & 0xf;
    hdr->numQ = ntohs(*(unsigned short*)(buffer + 4));
    hdr->numA = ntohs(*(unsigned short*)(buffer + 6));
    hdr->auRR = ntohs(*(unsigned short*)(buffer + 8));
    hdr->adRR = ntohs(*(unsigned short*)(buffer + 10));

    /* Process the data of DNS starting at buffer + sizeof(dns_hdr) */


    // int offset = lookup_domains(buffer, &hdr);

    if (hdr->qr != 0) {
        perror("not query");
        return -1; 
    }

    hdr->qr = 1;     // Will make into a response
    hdr->numA = 0;   // Processing only questions from client
    hdr->auRR = 0;   // Not implemented
    hdr->adRR = 0;   // Not implemented

    unsigned short offset = sizeof(dns_hdr);


    unsigned char ans[MAX_IPS * hdr->numQ][ANS_LENGTH];    // Will be appended to after the questions to make response
    // For every requested domain name
    for (int i = 0; i < hdr->numQ; i++) {
        dns_entry map;
        unsigned short domain_ptr = offset | 0xC000;        // To be used as domain pointer in answer
        // Parses the ith domain in the request and stores in map.domain
        // Leaves buffer untouched and offset will point to next byte to be read
        offset = process_domain(offset, buffer, map.domain, 0);

        unsigned short type = ntohs(*(unsigned short*)(buffer + offset));
        if (type != 0x0001) {      /* All types but A (IPv4) Not Implemented */
            hdr->rcd = 4;
            return (int) offset + 4;
            // return offset + 4; // TODO: For now, idk how to end ill bounce back to client somehow
        }

        unsigned short class = ntohs(*(unsigned short*)(buffer + offset + 2));
        if (class != 0x0001) {      /* All classes but IN (Internet Class) Not Implemented */
            hdr->rcd = 4;
            return (int) offset + 4;
            // return offset + 4; // TODO: For now, idk if right value bc ending early
        }
        offset += 4;

        // Looks up the ith domain stored in map.domain and stores the dns_entry in map
        // Will either retreive from table or retrieve upstream
        if (get_domain(&map, offset, buffer) < 0) {
            return -1; 
        }

        // TODO: Contruct answers here and store somewhere ill have to process all questions before putting at end of the buffer
        // After that we can do the next question

        // answers:
        // first 2 bytes is ptr to domain name
        // then 2 bytes for type then class
        // 4 bytes for time ot live 
        // 2 bytes data length
        // 4 bytes for ip address (in order of normal bytes)

        for (int j = hdr->numA; j < hdr->numA + map.numIp; j++) {
            // We need to represent the domain name as pointer
            *(unsigned short*)(ans[j]) = htons(domain_ptr);
            *(unsigned short*)(ans[j] + 2) = htons(type);
            *(unsigned short*)(ans[j] + 4) = htons(class);
            *(unsigned int*)(ans[j] + 6) = htonl((unsigned int)(map.ttl - time(NULL)));
            *(unsigned short*)(ans[j] + 10) = htons(IP_LENGTH);
            for (int k = 0; k < IP_LENGTH; k++) ans[j][12 + k] = map.ip[k];
        }
        hdr->numA += map.numIp;

    }

    // Append buffer with answers
    strncpy(buffer + offset, ans[0], hdr->numA * ANS_LENGTH);
    offset += hdr->numA * ANS_LENGTH;

    return (int) offset;
}

// int lookup_domains(char *buffer, dns_hdr *hd) {
//     hd->auRR = 0;
//     hd->adRR = 0;
//     int offset = sizeof(dns_hdr);
//     for (int i = 0; i < hd->numQ; i++) {
//         dns_entry map;
//         int index = 0;
//         while (true) {
//             int i = 0;
//             for ( ; i < buffer[offset]; ) {
//                 map.domain[index++] = buffer[offset + ++i];
//             }
//             offset += ++i;
//             if (!buffer[offset]) break;
//             map.domain[index++] = '.';
//         }
//         map.domain[index] = '\0';
// // get_domain(sInt, dns_addr, len, buffer);
//         unsigned short type = ntohs(*(unsigned short*)(buffer + ++offset));
//         // TODO: Commented out for now, have to decide what types to implement. will start with just IPv4 but might add stuff like email later idk
//         // switch (type) {
//         //     case 0x0001:        /* A (IPv4) */
//         //         // Lookup IPv4 and construct response
//         //         break;
//         //     case 0x001C:        /* AAAA (IPv6) */
//         //         // Lookup IPv6 and construct response
//         //         break;
//         //     default:            /* Non IP Type Not Implemented */
//         //         hd->rcd = 4;
//         //         return offset + 4; // TODO: For now, idk if right value bc ending early
//         // }
//         if (type != 0x0001) {      /* Non Internet Class Not Implemented */
//             hd->rcd = 4;
//             return offset + 4; // TODO: For now, idk if right value bc ending early
//         }
//         unsigned short class = ntohs(*(unsigned short*)(buffer + offset + 2));
//         if (class != 0x0001) {      /* Non Internet Class Not Implemented */
//             hd->rcd = 4;
//             return offset + 4; // TODO: For now, idk if right value bc ending early
//         }
//         offset += 4;
//     }
//     // offset at the end of the packet if no answers
//     // answers:
//     // first 2 bytes indicates the domain name somehow
//     // then 2 bytes for type then class
//     // 4 bytes for time ot live 
//     // 2 bytes data length
//     // 4 bytes for ip address (in order of normal bytes)
//     return offset;
// }

void shutdown(int rx_fd, int tx_fd) {
    char buffer[256];
    ssize_t count;
    
    while ((count = read(rx_fd, buffer, sizeof(buffer))) > 0) {
        // Process command from router
        if (strcmp(buffer, "shutdown") == 0) break;
        
        // Implementation logic
        write(tx_fd, "DNS: Processed command\n", 24);
    }

    // Clean shutdown on EOF or explicit command
    write(tx_fd, "DNS: Shutting down\n", 19);
    close(rx_fd);
    close(tx_fd);
    exit(EXIT_SUCCESS);
}