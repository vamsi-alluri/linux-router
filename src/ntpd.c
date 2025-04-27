#include "ntpd.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>

#define NTP_TIMESTAMP_DELTA 2208988800ull // Difference between UNIX and NTP start time
#define NTPD_PORT 123                     // Well-known port
#define DEFAULT_REFRESH 14400             // 4 hours in seconds
#define DEFAULT_SERVER "time.google.com"  // TODO: set default server hostname here

unsigned char server_hostname[255];

void ntp_main(int rx_fd, int tx_fd)
{
    // Send the PID back to the parent for processing
    pid_t pid = getpid();
    write(tx_fd, &pid, sizeof(pid_t)); // Send the pid to be stored by the parent process.

    memset(&server_hostname, 0, sizeof(server_hostname));
    strncpy(server_hostname, DEFAULT_SERVER, sizeof(DEFAULT_SERVER) - 1);
    server_hostname[sizeof(DEFAULT_SERVER) - 1] = '\0'; // Null-terminate

    last_refresh = refresh_time();
    refresh_interval = DEFAULT_REFRESH;

    struct sockaddr_in ser_addr, cli_addr;
    int flags, s, slen = sizeof(cli_addr), recv_len, send_len, select_ret;

    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        perror("socket");
        return;
    }

    struct ifreq myreq;
    memset(&myreq, 0, sizeof(myreq));
    strncpy(myreq.ifr_name, "enp0s8", IFNAMSIZ);

    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, (void *)&myreq, sizeof(myreq)) < 0)
    {
        perror("setsockopt");
        close(s);
        return;
    }

    if (flags = fcntl(s, F_GETFL) < 0)
    {
        perror("F_GETFL");
        close(s);
        return;
    }
    flags |= O_NONBLOCK;
    if (fcntl(s, F_SETFL, flags) < 0)
    {
        perror("F_SETFL");
        close(s);
        return;
    }

    memset((char *)&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_port = htons(NTPD_PORT);
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *)&ser_addr, sizeof(ser_addr)) < 0)
    {
        perror("bind");
        close(s);
        return;
    }

    // system("clear");
    printf("...This is NTP server (Non-Blocking Version) listening on port %d...\n\n", NTPD_PORT);

    struct timeval tv = {5, 0}; // 5 seconds, 0 microseconds
    fd_set rfds;
    while (true)
    {
        FD_ZERO(&rfds);
        FD_SET(s, &rfds);
        FD_SET(rx_fd, &rfds);

        // Check if time refresh is due
        if (time(NULL) - last_refresh >= refresh_interval)
        {
            last_refresh = refresh_time();
        }

        if (select_ret = select(s + 1, &rfds, NULL, NULL, &tv) < 0)
        {
            perror("select");
            continue;
        }
        else if (select_ret == 0)
            continue; // Timeout

        // For reading & processing commands from router
        if (FD_ISSET(rx_fd, &rfds))
        {
            char buffer[256];
            ssize_t count;

            char command[256];
            int pos = 0;

            while ((count = read(rx_fd, buffer, sizeof(buffer))) > 0)
            {
                for (int i = 0; i < count; i++)
                {
                    if (buffer[i] == '\n')
                    {
                        command[pos] = '\0';
                        handle_ntp_command(rx_fd, tx_fd, command);
                        pos = 0;
                    }
                    else
                    {
                        command[pos++] = buffer[i];
                    }
                }
            }
        }

        // For reading & processing incoming NTP queries from clients
        if (FD_ISSET(s, &rfds))
        {
            ntp_packet in_packet;
            memset(&in_packet, 0, sizeof(in_packet));
            if ((recv_len = recvfrom(s, &in_packet, sizeof(in_packet), 0,
                                     (struct sockaddr *)&cli_addr, &slen)) < 0)
            {
                perror("recvfrom");
                continue;
            }

            printf("Received packet from %s, port number:%d\n",
                   inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

            if (in_packet.mode != 3)
            {
                perror("ignore non client ntp request");
                continue;
            }
            if (in_packet.vn != 4)
            {
                perror("version number of request not 4, but still reply");
            }

            // Contruct reply
            ntp_packet out_packet;
            memset(&out_packet, 0, sizeof(out_packet));
            out_packet.li = 0;    // No warning
            out_packet.vn = 4;    // Version 4
            out_packet.mode = 4;  // Server
            out_packet.strat = 4; // Secondary Server (using local router time, not GPS)
            out_packet.xmt = htonll(time(NULL)              // Local UNIX time + Diff btwn UNIX and NTP times,
                                    + NTP_TIMESTAMP_DELTA); // then convert byte order for 8 byte time

            if ((send_len = sendto(s, &out_packet, sizeof(out_packet), 0,
                                   (struct sockaddr *)&cli_addr, slen)) < 0)
            {
                perror("sendto");
                continue;
            }

            printf("Sent packet to %s, port number:%d\n",
                   inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
        }
    }
    close(s);
    return;
}

time_t refresh_time()
{
    ntp_packet refresh_packet;
    memset(&refresh_packet, 0, sizeof(ntp_packet));

    // Populate packet
    refresh_packet.li = 0;   // LI = 0
    refresh_packet.vn = 4;   // VN = 4
    refresh_packet.mode = 3; // Mode = 3 (Client)

    // Creates a socket
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("cannot create socket\n");
        return time(NULL);
    }

    // Connects the socket to the server’s IP address and port number
    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(NTPD_PORT);
    struct hostent *hostinfo = gethostbyname(server_hostname);
    if (hostinfo == 0)
    {
        perror(server_hostname);
        perror(" is invalid host\n");
        return time(NULL);
    }
    saddr.sin_addr.s_addr = *((unsigned int *)(hostinfo->h_addr_list[0]));
    if (connect(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
    {
        perror("cannot connect refresh\n");
        return time(NULL);
    }

    printf("Sending refresh to host %s, port number:%d\n",
           inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));

    // Sends the request to the server. (Use send() instead of sendto())
    if (send(sock, &refresh_packet, sizeof(ntp_packet), 0) < 0)
    {
        perror("send refresh\n");
        return time(NULL);
    }

    int reply_length = recv(sock, &refresh_packet, sizeof(ntp_packet), 0);
    if (reply_length != sizeof(ntp_packet))
    {
        perror("recv refresh\n");
        return time(NULL);
    }

    printf("Received refresh from host %s, port number:%d\n",
           inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));

    // Extract time from packet and update local time
    unsigned long newTimeSec = ntohll(refresh_packet.xmt >> 32) - NTP_TIMESTAMP_DELTA;

    printf("Server time: %ld (Unix seconds)\n", newTimeSec);

    // Set local time to retrieved time
    struct timeval tv;
    tv.tv_sec = newTimeSec;
    tv.tv_usec = 0; // No microseconds

    if (settimeofday(&tv, NULL) < 0)
    {
        perror("settimeofday\n");
        return time(NULL);
    }
    return time(NULL);
}

void handle_ntp_command(int rx_fd, int tx_fd, unsigned char *command)
{
    // Handle each command and write reply to tx_fd
    if (strncmp(command, "shutdown", 9) == 0)
    {
        // Clean shutdown on EOF or explicit command
        write(tx_fd, "NTP: Shutting down\n", 19);
        close(rx_fd); // Close pipes before exit
        close(tx_fd);
        exit(EXIT_SUCCESS);
    }
    else if (strncmp(command, "server ", 7) == 0)
    {
        strncpy(server_hostname, command + 7, strlen(command + 7) - 1);
        server_hostname[sizeof(command + 7) - 1] = '\0'; // Null-terminate
        write(tx_fd, "NTP: Saved NTP Server\n", 22);
    }
    else if (strncmp(command, "refresh", 8) == 0)
    {
        last_refresh = refresh_time();
        write(tx_fd, "NTP: Refreshed Local Time\n", 26);
    }
    else if (strncmp(command, "interval ", 9) == 0)
    {
        char temp[50];
        strncpy(temp, command + 9, strlen(command + 9) - 1);
        temp[sizeof(command + 9) - 1] = '\0'; // Null-terminate
        refresh_interval = atoi(temp);
        write(tx_fd, "NTP: Changed Refresh Interval\n", 30);
    }
    else
    {
        write(tx_fd, "NTP: Unknown Command\n", 21);
    }
    // TODO: maybe add more commands
}