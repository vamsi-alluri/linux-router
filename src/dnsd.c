#include "dnsd.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#define DNSD_PORT 53        // Well-known port
#define BUFFER_SIZE 500

void dns_main(int rx_fd, int tx_fd){
    // Send the PID back to the parent for processing
    pid_t pid = getpid();
    write(tx_fd, &pid, sizeof(pid_t)); // Send the pid to be stored by the parent process. 

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
    ser_addr.sin_port = htons(DNSD_PORT);
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *)&ser_addr, sizeof(ser_addr)) < 0) {
        perror("bind");
        close(s);
        return -1;
    }

    // system("clear");
    printf("...This is DNS server (Non-Blocking Version) listening on port %d...\n\n", DNSD_PORT);

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

        dns_hdr in_hdr;
        memset(&in_hdr, 0, sizeof(in_hdr));
        
        // Format for DNS header
        in_hdr.id = ntohs(*(unsigned short*)buffer);
        unsigned short flags = ntohs(*(unsigned short*)(buffer + 2));
        in_hdr.qr = (flags >> 15) & 0x1;
        in_hdr.op = (flags >> 11) & 0xf;
        in_hdr.aa = (flags >> 10) & 0x1;
        in_hdr.tc = (flags >> 9) & 0x1;
        in_hdr.rd = (flags >> 8) & 0x1;
        in_hdr.ra = (flags >> 7) & 0x1;
        in_hdr.z = (flags >> 6) & 0x1;
        in_hdr.ad = (flags >> 5) & 0x1;
        in_hdr.cd = (flags >> 4) & 0x1;
        in_hdr.rcd = flags & 0xf;
        in_hdr.numQ = ntohs(*(unsigned short*)(buffer + 4));
        in_hdr.numA = ntohs(*(unsigned short*)(buffer + 6));
        in_hdr.auRR = ntohs(*(unsigned short*)(buffer + 8));
        in_hdr.adRR = ntohs(*(unsigned short*)(buffer + 10));



        /* Process the data of DNS starting at buffer + sizeof(dns_hdr) */


        int offset = 12; // TBD
        dns_hdr out_hdr;
        memset(&out_hdr, 0, sizeof(out_hdr));


        /* Set the data of DNS response header */


        unsigned char response[BUFFER_SIZE];
        memset(response, '\0', BUFFER_SIZE);

        // Format for DNS response
        *(unsigned short*)(response + 0) = htons(out_hdr.id);
        flags = 0;
        flags |= (out_hdr.qr & 0x1) << 15;
        flags |= (out_hdr.op & 0xf) << 11;
        flags |= (out_hdr.aa & 0x1) << 10;
        flags |= (out_hdr.tc & 0x1) << 9;
        flags |= (out_hdr.rd & 0x1) << 8;
        flags |= (out_hdr.ra & 0x1) << 7;
        flags |= (out_hdr.z & 0x1) << 6;
        flags |= (out_hdr.ad & 0x1) << 5;
        flags |= (out_hdr.cd & 0x1) << 4;
        flags |= out_hdr.rcd & 0xf;
        *(unsigned short*)(response + 2) = htons(flags);
        *(unsigned short*)(response + 4) = htons(out_hdr.numQ);
        *(unsigned short*)(response + 6) = htons(out_hdr.numA);
        *(unsigned short*)(response + 8) = htons(out_hdr.auRR);
        *(unsigned short*)(response + 10) = htons(out_hdr.adRR);



        /* Set the data of DNS starting at response + sizeof(dns_hdr) */



        if ((send_len = sendto(s, response, offset, 0,
                                    (struct sockaddr *)&cli_addr, &slen)) < 0) {
            perror("sendto");
            continue;
        }

        printf("Sent packet to %s, port number:%d\n",
                inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
    }
    close(s);
    return 0;
}


// TODO
// void shutdown(int rx_fd, int tx_fd) {
//     char buffer[256];
//     ssize_t count;
    
//     while ((count = read(rx_fd, buffer, sizeof(buffer))) > 0) {
//         // Process command from router
//         if (strcmp(buffer, "shutdown") == 0) break;
        
//         // Implementation logic
//         write(tx_fd, "DNS: Processed command\n", 24);
//     }

//     // Clean shutdown on EOF or explicit command
//     write(tx_fd, "DNS: Shutting down\n", 19);
//     close(rx_fd);
//     close(tx_fd);
//     exit(EXIT_SUCCESS);
// }