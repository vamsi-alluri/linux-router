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
#include <net/if.h>

#define NTP_TIMESTAMP_DELTA 2208988800ul  // Difference between UNIX and NTP start time
#define NTPD_PORT 123                     // Well-known port
#define REFRESH_PORT 32432                // Arbitrary unused port & ignored by NAT
#define DEFAULT_REFRESH 14400             // 4 hours in seconds
#define DEFAULT_SERVER "time.google.com"  // TODO: set default server hostname here
#define MAX_LOG_SIZE 5 * 1024 * 1024      // 5MB default
#define DEFAULT_NTP_LOG_PATH "/root/linux-router/bin/logs/ntp.log"

static char *ntp_log_file_path = DEFAULT_NTP_LOG_PATH;

static void clear_log_file_ntp() {
    FILE *log_file = fopen(ntp_log_file_path, "w");
    if (log_file) {
        fprintf(log_file, "\n\n");
        fclose(log_file);
        append_ln_to_log_file_ntp("Log file cleared.");
    }
}

static void vappend_ln_to_log_file_ntp(const char *msg, va_list args) {

    // Clean up the log file if the size is more than 10 MB.
    va_list argp;  

    FILE *log_file = fopen(ntp_log_file_path, "r");
    if (log_file) {
        fseek(log_file, 0, SEEK_END);
        long file_size = ftell(log_file);
        fclose(log_file);
        
        if (file_size > MAX_LOG_SIZE) {
            clear_log_file_ntp();
            append_ln_to_log_file_ntp("Log file size exceeded %d bytes.", MAX_LOG_SIZE);
        }
    }

    if (msg == NULL || strcmp("", msg) == 0){
        log_file = fopen(ntp_log_file_path, "a");
        if (log_file) {
            fprintf(log_file, "\n");
            fclose(log_file);
        }
        return;
    }

    time_t now = time(NULL);
    char buffer[26];
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    log_file = fopen(ntp_log_file_path, "a");
    if (log_file) {
        fprintf(log_file, "[%s] ", buffer);
        vfprintf(log_file, msg, args);
        fprintf(log_file, "\n");
        fclose(log_file);
    }
}

void append_ln_to_log_file_ntp(const char *msg, ...) {
    
    va_list args;
    va_start(args, msg);
    vappend_ln_to_log_file_ntp(msg, args);
    va_end(args);
}

void append_ln_to_log_file_ntp_verbose(const char *msg, ...) {
    // if (verbose != 1) return;

    // va_list args;
    // va_start(args, msg);
    // vappend_ln_to_log_file_ntp(msg, args);
    // va_end(args);
}

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
        append_ln_to_log_file_ntp("socket");
        return;
    }

    struct ifreq myreq;
    memset(&myreq, 0, sizeof(myreq));
    strncpy(myreq.ifr_name, "enp0s8", IFNAMSIZ);

    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, (void *)&myreq, sizeof(myreq)) < 0)
    {
        append_ln_to_log_file_ntp("setsockopt");
        close(s);
        return;
    }

    if ((flags = fcntl(s, F_GETFL)) < 0)
    {
        append_ln_to_log_file_ntp("F_GETFL");
        close(s);
        return;
    }
    flags |= O_NONBLOCK;
    if (fcntl(s, F_SETFL, flags) < 0)
    {
        append_ln_to_log_file_ntp("F_SETFL");
        close(s);
        return;
    }

    memset((char *)&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_port = htons(NTPD_PORT);
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *)&ser_addr, sizeof(ser_addr)) < 0)
    {
        append_ln_to_log_file_ntp("bind");
        close(s);
        return;
    }

    // system("clear");
    append_ln_to_log_file_ntp("...This is NTP server (Non-Blocking Version) listening on port %d...\n\n", NTPD_PORT);

    struct timeval tv = {5, 0}; // 5 seconds, 0 microseconds
    fd_set rfds;
    while (true)
    {
        tv.tv_sec = 5;  // Reset timeout before each select call
        tv.tv_usec = 0;

        FD_ZERO(&rfds);
        FD_SET(s, &rfds);
        FD_SET(rx_fd, &rfds);

        // Check if time refresh is due
        if (time(NULL) - last_refresh >= refresh_interval)
        {
            last_refresh = refresh_time();
        }

        int ready = select(((s > rx_fd) ? s : rx_fd) + 1, &rfds, NULL, NULL, &tv);
        if (ready < 0) {
            append_ln_to_log_file_dns("select");
            continue;
        }
        // else if (select_ret == 0)
        //     continue; // Timeout

        // For reading & processing commands from router
        if (FD_ISSET(rx_fd, &rfds))
        {
            append_ln_to_log_file_ntp("I see something on rx_fd");
            char buffer[256];
            ssize_t count;

            // char command[256];
            // int pos = 0;

            if ((count = read(rx_fd, buffer, sizeof(buffer))) > 0)
            {
                append_ln_to_log_file_ntp("I read something on rx_fd");
                append_ln_to_log_file_ntp("count is %d, buffer is %s", count, buffer);
                // for (int i = 0; i < count; i++)
                // {
                //     if (buffer[i] == '\n')
                //     {
                //         command[pos] = '\0';
                //         handle_ntp_command(rx_fd, tx_fd, command);
                //         pos = 0;
                //     }
                //     else
                //     {
                //         command[pos++] = buffer[i];
                //     }
                // }
                buffer[count - 1] = '\0';
                handle_ntp_command(rx_fd, tx_fd, buffer);
            }
            else {
               handle_ntp_command(rx_fd, tx_fd, "shutdown"); 
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
                append_ln_to_log_file_ntp("recvfrom");
                continue;
            }

            append_ln_to_log_file_ntp("Received packet from %s, port number:%d\n",
                   inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

            // if (in_packet.mode != 3)
            // Had to change from bit fields
            if ((in_packet.li_vn_mode & 0b00000111) != 3)
            {
                append_ln_to_log_file_ntp("ignore non client ntp request");
                continue;
            }
            // if (in_packet.vn != 4)
            // Had to change from bit fields
            if ((in_packet.li_vn_mode & 0b00111000) != 4)
            {
                append_ln_to_log_file_ntp("version number of request not 4, but still reply");
            }

            // Contruct reply
            ntp_packet out_packet;
            memset(&out_packet, 0, sizeof(out_packet));
            // out_packet.li = 0;    // No warning
            // out_packet.vn = 4;    // Version 4
            // out_packet.mode = 4;  // Server
            // Had to change from bit fields
            out_packet.li_vn_mode = 0b00100100;
            out_packet.strat = 4; // Secondary Server (using local router time, not GPS)
            out_packet.xmtSec = htonl(time(NULL)              // Local UNIX time + Diff btwn UNIX and NTP times,
                                    + NTP_TIMESTAMP_DELTA); // then convert byte order for 8 byte time

            if ((send_len = sendto(s, &out_packet, sizeof(out_packet), 0,
                                   (struct sockaddr *)&cli_addr, slen)) < 0)
            {
                append_ln_to_log_file_ntp("sendto");
                continue;
            }

            append_ln_to_log_file_ntp("Sent packet to %s, port number:%d\n",
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
    // refresh_packet.li = 0;   // LI = 0
    // refresh_packet.vn = 4;   // VN = 4
    // refresh_packet.mode = 3; // Mode = 3 (Client)

    // Had to change from bit fields
    refresh_packet.li_vn_mode = 0b00100011;

    // Creates a socket
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        append_ln_to_log_file_ntp("cannot create socket\n");
        return time(NULL);
    }

    struct sockaddr_in local_saddr;
    memset(&local_saddr, 0, sizeof(local_saddr));
    local_saddr.sin_family = AF_INET;
    local_saddr.sin_port = htons(REFRESH_PORT);
    local_saddr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Bind socket to a unsurveiled port by NAT
    if (bind(sock, (struct sockaddr *)&local_saddr, sizeof(local_saddr)) < 0) {
        append_ln_to_log_file_ntp("cannot bind refresh\n");
        close(sock);
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
        append_ln_to_log_file_ntp("%s is invalid host\n", server_hostname);
        close(sock);
        return time(NULL);
    }
    saddr.sin_addr.s_addr = *((unsigned int *)(hostinfo->h_addr_list[0]));
    if (connect(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
    {
        append_ln_to_log_file_ntp("cannot connect refresh\n");
        close(sock);
        return time(NULL);
    }

    // Set a receive timeout so recv doesn't stall
    struct timeval utv;
    utv.tv_sec = 3;  // 3 seconds
    utv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&utv, sizeof(utv));

    append_ln_to_log_file_ntp("Sending refresh to host %s, port number:%d\n",
           inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));

    // Sends the request to the server. (Use send() instead of sendto())
    if (send(sock, &refresh_packet, sizeof(ntp_packet), 0) < 0)
    {
        append_ln_to_log_file_ntp("send refresh\n");
        close(sock);
        return time(NULL);
    }

    int reply_length = recv(sock, &refresh_packet, sizeof(ntp_packet), 0);
    if (reply_length != sizeof(ntp_packet))
    {
        append_ln_to_log_file_ntp("recv refresh\n");
        close(sock);
        return time(NULL);
    }

    append_ln_to_log_file_ntp("Received refresh from host %s, port number:%d\n",
           inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));

    // Extract time from packet and update local time
    unsigned long newTimeSec = ntohl(refresh_packet.xmtSec) - NTP_TIMESTAMP_DELTA;

    append_ln_to_log_file_ntp("Server time: %ld (Unix seconds)\n", newTimeSec);

    // Set local time to retrieved time
    struct timeval tv;
    tv.tv_sec = newTimeSec;
    tv.tv_usec = 0; // No microseconds

    if (settimeofday(&tv, NULL) < 0)
    {
        append_ln_to_log_file_ntp("settimeofday\n");
        close(sock);
        return time(NULL);
    }
    close(sock); // Made sure to close so we can use again
    return time(NULL);
}

void handle_ntp_command(int rx_fd, int tx_fd, unsigned char *command)
{
    append_ln_to_log_file_ntp("I try to handle something on rx_fd");
    // Handle each command and write reply to tx_fd
    if (strcmp(command, "shutdown") == 0)
    {
        append_ln_to_log_file_ntp("I am shutting down");
        // Clean shutdown on EOF or explicit command
        write(tx_fd, "NTP: Acknowledged shutdown command.\n", 36);
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
