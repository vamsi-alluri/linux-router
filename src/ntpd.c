#include "ntpd.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#define NTP_TIMESTAMP_DELTA 2208988800ull // Difference between UNIX and NTP start time
#define NTPD_PORT 123

void ntp_main(int rx_fd, int tx_fd){
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
    ser_addr.sin_port = htons(NTPD_PORT);
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *)&ser_addr, sizeof(ser_addr)) < 0) {
        perror("bind");
        close(s);
        return -1;
    }

    // system("clear");
    printf("...This is NTP server (Non-Blocking Version) listening on port %d...\n\n", NTPD_PORT);

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

        ntp_packet in_packet;
        memset(&in_packet, 0, sizeof(in_packet));
        if ((recv_len = recvfrom(s, &in_packet, sizeof(in_packet), 0,
                                    (struct sockaddr *)&cli_addr, &slen)) < 0) {
            perror("recvfrom");
            continue;
        }

        printf("Received packet from %s, port number:%d\n",
                inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

        ntp_packet out_packet;
        memset(&out_packet, 0, sizeof(out_packet));
        out_packet.li = 0;                          // No warning
        out_packet.vn = 4;                          // Version 4
        out_packet.mode = 4;                        // Server
        out_packet.strat = 4;                       // Secondary Server (using local router time, not GPS)
        out_packet.xmt = htonll(time(NULL)          // Local UNIX time + Diff btwn UNIX and NTP times, 
                            + NTP_TIMESTAMP_DELTA); // then convert byte order for 8 byte time 

        if ((send_len = sendto(s, &out_packet, sizeof(out_packet), 0,
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
//         write(tx_fd, "NTP: Processed command\n", 24);
//     }

//     // Clean shutdown on EOF or explicit command
//     write(tx_fd, "NTP: Shutting down\n", 19);
//     return 0;
// }