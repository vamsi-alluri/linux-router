#include "dnsd.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>

#define DNS_PORT 53              // Well-known port
#define LOOKUP_PORT 31534        // Arbitrary unused port & ignored by NAT
#define BUFFER_SIZE 500
#define CLEANUP_INTERVAL 600     // Once every 5 min.
#define MAX_LOG_SIZE 5 * 1024 * 1024    // 5MB default
#define DEFAULT_DNS_LOG_PATH "/root/linux-router/bin/logs/dns.log"
#define DEFAULT_WAN_IFACE "enp0s3"
#define DEFAULT_LAN_IFACE "enp0s8"

static char *dns_log_file_path = DEFAULT_DNS_LOG_PATH;
int read_from_router_pipe, write_to_router_pipe;

static void clear_log_file_dns() {
    FILE *log_file = fopen(dns_log_file_path, "w");
    if (log_file) {
        fprintf(log_file, "\n\n");
        fclose(log_file);
        append_ln_to_log_file_dns_verbose("Log file cleared.");
    }
}

static void vappend_ln_to_log_file_dns(const char *msg, va_list args) {

    // Clean up the log file if the size is more than 10 MB.
    va_list argp;  

    FILE *log_file = fopen(dns_log_file_path, "r");
    if (log_file) {
        fseek(log_file, 0, SEEK_END);
        long file_size = ftell(log_file);
        fclose(log_file);
        
        if (file_size > MAX_LOG_SIZE) {
            clear_log_file_dns();
            append_ln_to_log_file_dns("Log file size exceeded %d bytes.", MAX_LOG_SIZE);
        }
    }

    if (msg == NULL || strcmp("", msg) == 0){
        log_file = fopen(dns_log_file_path, "a");
        if (log_file) {
            fprintf(log_file, "\n");
            fclose(log_file);
        }
        return;
    }
    
    time_t now = time(NULL);
    char buffer[26];
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", localtime(&now));

    log_file = fopen(dns_log_file_path, "a");
    if (log_file) {
        fprintf(log_file, "[%s] ", buffer);
        vfprintf(log_file, msg, args);
        fprintf(log_file, "\n");
        fclose(log_file);
    }
}

void append_ln_to_log_file_dns(const char *msg, ...) {
    
    va_list args;
    va_start(args, msg);
    vappend_ln_to_log_file_dns(msg, args);
    va_end(args);
}

void append_ln_to_log_file_dns_verbose(const char *msg, ...) {
    if (verbose_g != 1) return;

    va_list args;
    va_start(args, msg);
    vappend_ln_to_log_file_dns(msg, args);
    va_end(args);
}


int get_machine_ip_dns(const char *iface, unsigned char gateway_ip[IP_LENGTH], size_t size) {

    int temp_sock;  // Temporary socket for IP lookup
    struct ifreq ifr;

    // Get IP address using a temporary socket
    if((temp_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        append_ln_to_log_file_nat("Temp socket creation failed on iface %s.", iface);
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if(ioctl(temp_sock, SIOCGIFADDR, &ifr) < 0) {
        append_ln_to_log_file_nat("IP address retrieval failed on iface %s. Continuing without it.", iface);
        close(temp_sock);
    }
    
    // Store IP
    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    uint32_t ip_buffer = ip_addr->sin_addr.s_addr;
    for (int i = 0; i < IP_LENGTH; i++)  gateway_ip[i] = (ip_buffer >> (8*i)) & 0xFF;
    close(temp_sock);
}

void dns_main(int rx_fd, int tx_fd, int verbose_p, char * parent_dir){

    if (chdir(parent_dir) < 0) {
        fprintf(tx_fd, "Error changing directory to %s\n", parent_dir);
    } else {
        char cwd[256];
        getcwd(cwd, 256);
        fprintf(tx_fd, "Changed directory to %s\n", cwd);
    }
    
    read_from_router_pipe = rx_fd;
    write_to_router_pipe = tx_fd;
    verbose_g = verbose_p;

    // Send the PID back to the parent for processing
    pid_t pid = getpid();
    write(write_to_router_pipe, &pid, sizeof(pid_t)); // Send the pid to be stored by the parent process. 
    
    append_ln_to_log_file_dns_verbose("DNS service started.");
    memset(domain_table, 0, MAX_ENTRIES * sizeof(dns_bucket *));   // Clear domain_table

    // Add a dummy value to the table at 0 that will be used for iterating through it
    if ((domain_table[0] = malloc(sizeof(dns_bucket))) == NULL) append_ln_to_log_file_dns_verbose("malloc");
    memset(domain_table[0], 0, sizeof(dns_bucket));
    domain_table[0]->entry.ttl = LONG_MAX;
    domain_table[0]->next = domain_table[0];

    // Add router as a domain name for router's LAN IP address
    get_machine_ip_dns(DEFAULT_LAN_IFACE, lan_machine_ip_str_dns, sizeof(lan_machine_ip_str_dns));
    unsigned char ipR[MAX_IPS][IP_LENGTH];
    // TODO: replace with ip constant if saved somewhere
    for (int i = 0; i < IP_LENGTH; i++) ipR[0][i] = lan_machine_ip_str_dns[i];
    insert_table("router", ipR, LONG_MAX, 1);

    last_cleanup = time(NULL);

    struct sockaddr_in ser_addr, cli_addr;
    int flags, s, slen = sizeof(cli_addr), recv_len, send_len, select_ret;

    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        append_ln_to_log_file_dns_verbose("socket Error");
        return;
    }

    struct ifreq myreq;
    memset(&myreq, 0, sizeof(myreq));
    strncpy(myreq.ifr_name, DEFAULT_LAN_IFACE, IFNAMSIZ);
    
    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, (void *)&myreq, sizeof(myreq)) < 0) {
        append_ln_to_log_file_dns_verbose("setsockopt Error");
        close(s);
        return;
    }

    if ((flags = fcntl(s, F_GETFL)) < 0) {
        append_ln_to_log_file_dns_verbose("F_GETFL");
        close(s);
        return;
    }
    flags |= O_NONBLOCK;
    if (fcntl(s, F_SETFL, flags) < 0) {
        append_ln_to_log_file_dns_verbose("F_SETFL Error");
        close(s);
        return;
    }

    memset((char *)&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_port = htons(DNS_PORT);
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Bind socket to a unsurveiled port by NAT
    if (bind(s, (struct sockaddr *)&ser_addr, sizeof(ser_addr)) < 0) {
        append_ln_to_log_file_dns_verbose("bind error");
        close(s);
        return;
    }

    // system("clear");
    append_ln_to_log_file_dns_verbose("...This is DNS server (Non-Blocking Version) listening on port %d...\n\n", DNS_PORT);

    struct timeval tv = {5, 0}; // 5 seconds, 0 microseconds
    fd_set rfds;
    while (true) {
        tv.tv_sec = 5;  // Reset timeout before each select call
        tv.tv_usec = 0;
    
        FD_ZERO(&rfds);
        FD_SET(s, &rfds);
        FD_SET(rx_fd, &rfds);

        // Check if cleanup is due  
        time_t now = time(NULL);  
        if (now - last_cleanup >= CLEANUP_INTERVAL) {  
            clean_table(false);  
            last_cleanup = now;  
        }

        int ready = select(((s > rx_fd) ? s : rx_fd) + 1, &rfds, NULL, NULL, &tv);
        if (ready < 0) {
            append_ln_to_log_file_dns_verbose("select");
            continue;
        }
        // else if (select_ret == 0) continue; // Timeout

        // For reading & processing commands from router
        if (FD_ISSET(rx_fd, &rfds)) {
            char buffer[256];
            ssize_t count;
            if ((count = read(rx_fd, buffer, sizeof(buffer))) > 0)
            {
                buffer[count - 1] = '\0';
                handle_dns_command(rx_fd, tx_fd, buffer);
            }
            else {
               handle_dns_command(rx_fd, tx_fd, "shutdown"); 
            }
        }

        // For reading & processing incoming DNS queries from clients
        if (FD_ISSET(s, &rfds)) {

            unsigned char buffer[BUFFER_SIZE];
            memset(buffer, '\0', BUFFER_SIZE);

            if ((recv_len = recvfrom(s, buffer, BUFFER_SIZE, 0,
                                        (struct sockaddr *)&cli_addr, &slen)) < 0) {
                append_ln_to_log_file_dns_verbose("recvfrom");
                continue;
            }

            append_ln_to_log_file_dns_verbose("Received packet from %s, port number:%d\n",
                    inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

            dns_hdr hdr;
            int offset = process_packet(&hdr, buffer);
            
            if (offset < 0) continue;      // There was an error in get_domain so abandon this request

            if ((send_len = sendto(s, buffer, offset, 0,
                                        (struct sockaddr *)&cli_addr, slen)) < 0) {
                append_ln_to_log_file_dns_verbose("sendto");
                continue;
            }

            // Sent back packet if not implemented
            if (hdr.rcd != 0) {

                // Packet is identical to as it was received but with the Not implemented flag triggered.
                append_ln_to_log_file_dns_verbose("Sent failed packet back to %s, port number:%d\n",
                        inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
            }
            // If implemented, sent back an actual response
            else {
                append_ln_to_log_file_dns_verbose("Sent packet back to %s, port number:%d\n",
                        inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
            }
        }
    }
    close(s);
    return;
}

void handle_dns_command(int rx_fd, int tx_fd, unsigned char *command) {
    append_ln_to_log_file_dns_verbose("%s", command);
    if (strcmp(command, "shutdown") == 0) {
        // Clean shutdown on EOF or explicit command
        clean_table(true);
        write(tx_fd, "DNS: Acknowledged shutdown command.\n", 36);
        close(rx_fd); // Close pipes before exit
        close(tx_fd);
        exit(EXIT_SUCCESS);
    }
    else if (strcmp(command, "clean") == 0) {
        clean_table(false);  
        last_cleanup = time(NULL); 
        write(tx_fd, "DNS: Cleaned DNS Table.\n", 24); 
    }
    else if (strncmp(command, "set ", 4) == 0) {
        // TODO: Check if the domain name is alr in table and bounce back if so
        //
        dns_entry map;
        char *domain = command + 4;
        char *temp_ip = strchr(domain, ' ') + 1;
        *(temp_ip - 1) = '\0'; // Make sure domain is null terminated. temp_ip should be already
        if (domain == NULL || temp_ip == NULL) {
            write(tx_fd, "DNS: Incorrect Usage (set [Domain Name] [IPv4 Address])\n", 56);
            return;
        }
        unsigned char ip[MAX_IPS][IP_LENGTH];
        int index = 0;
        for (int i = 0; i < IP_LENGTH; i++) {
            char buf[4];
            int j = 0;
            for ( ; j < 4; j++, index++) {
                if (temp_ip[index] == '.' || temp_ip[index] == '\0') {
                    buf[j] = '\0';
                    break;
                }
                else {
                    buf[j] = temp_ip[index];
                }
            }
            index++;
            if (j == 0 || j == 4) { // If buf is empty or not null terminated by now
                write(tx_fd, "DNS: Incorrect Usage (set [Domain Name] [IPv4 Address])\n", 56);
                return;
            }
            ip[0][i] = atoi(buf);
            if (ip[0][i] > 255) { // Not valid IPv4 byte
                write(tx_fd, "DNS: Incorrect Usage (set [Domain Name] [IPv4 Address])\n", 56);
                return;
            }
        }


        if (insert_table(domain, ip, LONG_MAX, 1) != -1) {
            write(tx_fd, "DNS: Assigned Domain Name to IPv4 Address\n", 42);
        }
        else {
            write(tx_fd, "DNS: Domain Name Already Assigned to an IPv4 Address\n", 53);
        }
    }
    else if (strncmp(command, "unset ", 6) == 0) {
        // TODO: Check if the domain name is alr in table and bounce back if so
        //
        char *domain = command + 6;
        if (domain == NULL) {
            write(tx_fd, "DNS: Incorrect Usage (unset [Domain Name])\n", 43);
            return;
        }
        if (remove_table(domain) != -1) {
            write(tx_fd, "DNS: Unassigned Domain Name to IPv4 Address(es)\n", 48);
        }
        else {
            write(tx_fd, "DNS: Domain Name Not in DNS Table\n", 34);
        }
    }
    else if (strncmp(command, "upstream ", 9) == 0) {
        // TODO: Set the dns_ip to entered value
        //

        // Parse the IP address
        struct in_addr addr;
        if (inet_pton(AF_INET, command + 9, &addr) != 1) {
            write(tx_fd, "DNS: Incorrect Usage (upstream [IPv4 Address])\n", 47);
            return;
        }
        dns_ip = addr.s_addr;
        write(tx_fd, "DNS: Updated Upstream DNS IPv4 Address\n", 39);
    }
    else if (strcmp(command, "table") == 0) {
        char output[MAX_ENTRIES * 50];  // Big enough for many entries
        int offset = 0;
        // offset += snprintf(output + offset, sizeof(output) - offset, "DNS: Table Entries (  [Domain Name]  ||  [IPv4 Address 1] == [IPv4 Address 2] ...  ||  [Expiry Time]  )\n");
        offset += snprintf(output + offset, sizeof(output) - offset, "DNS: Table Entries\n");

        dns_bucket *start = domain_table[0];
        dns_bucket *prev = start;
        dns_bucket *curr = prev->next;
        while (start != curr) {
            // TODO: display info for each entry
            offset += snprintf(output + offset, sizeof(output) - offset, "Name: %s\nAddress(es):\n", curr->entry.domain);

            for (int i = 0; i < curr->entry.numIp; i++) {
                offset += snprintf(output + offset, sizeof(output) - offset, "\t%d.%d.%d.%d\n", curr->entry.ip[i][0], curr->entry.ip[i][1], curr->entry.ip[i][2], curr->entry.ip[i][3]);
                // if (i + 1 < curr->entry.numIp) offset += snprintf(output + offset, sizeof(output) - offset, " == ");
            }
            time_t ttl_time = curr->entry.ttl;
            if (ttl_time == LONG_MAX) {
                offset += snprintf(output + offset, sizeof(output) - offset, "Expires At: never (permanent alias)\n\n");
            }
            else {
                char buffer[26];
                strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", localtime(&ttl_time));
                offset += snprintf(output + offset, sizeof(output) - offset, "Expires At: %s\n\n", buffer);
            }

            // Move on to the next entry
            prev = curr;
            curr = prev->next;
        }
        write(tx_fd, output, offset);

        // write(tx_fd, "DNS: Table Entries (  [Domain Name]  ||  [IPv4 Address] ...  ||  [Expiry Time]  )\n", 75);

        // dns_bucket *start = domain_table[0];
        // dns_bucket *prev = start;
        // dns_bucket *curr = prev->next;

        // while (start != curr) {
        //     // TODO: display info for each entry
        //     write(tx_fd, curr->entry.domain, strlen(curr->entry.domain));
        //     write(tx_fd, "  ||  ", 6);

        //     for (int i = 0; i < curr->entry.numIp; i++) {
        //         char msg[30];
        //         snprintf(msg, sizeof(msg), "%d.%d.%d.%d", curr->entry.ip[i][0], curr->entry.ip[i][1], curr->entry.ip[i][2], curr->entry.ip[i][3]);
        //         write(tx_fd, msg, strlen(msg));
        //         if (i + 1 < curr->entry.numIp) write(tx_fd, " & ", 3);
        //     }
        //     write(tx_fd, "  ||  ", 6);
       
        //     time_t ttl_time = curr->entry.ttl;
        //     char buffer[26];
        //     strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", localtime(&ttl_time));
        //     write(tx_fd, buffer, strlen(buffer));
        //     write(tx_fd, "\n", 1);

        //     // Move on to the next entry
        //     prev = curr;
        //     curr = prev->next;
        // }
    }
    else {
        write(tx_fd, "DNS: Unknown Command\n", 21);
    }
}

int process_domain(unsigned short offset, unsigned char *buffer, unsigned char *domain, int index) {
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

unsigned long insert_table(unsigned char *domain, unsigned char ip[][IP_LENGTH], unsigned long ttl, int numIp) {
    unsigned long index = get_hash(domain);
    while (domain_table[index]) {
        if (strncmp(domain_table[index]->entry.domain, domain, strlen(domain_table[index]->entry.domain)) == 0) return -1; // Already in table
        index++;     // Linear probing
    }
    if ((domain_table[index] = malloc(sizeof(dns_bucket))) == NULL) append_ln_to_log_file_dns_verbose("malloc");
    memset(domain_table[index], 0, sizeof(dns_bucket));
    strncpy(domain_table[index]->entry.domain, domain, strlen(domain));
    domain_table[index]->entry.domain[MAX_DN_LENGTH-1] = '\0';
    domain_table[index]->entry.numIp = numIp;

    for (int i = 0; i < numIp; ++i) {
        for (int j = 0; j < IP_LENGTH; ++j) {
            domain_table[index]->entry.ip[i][j] = ip[i][j];
        }
    }

    domain_table[index]->entry.ttl = ttl;
    domain_table[index]->next = domain_table[0]->next;
    domain_table[0]->next = domain_table[index];
    return index;
}

unsigned int remove_table(unsigned char *domain) {
    dns_bucket *start = domain_table[0];
    dns_bucket *prev = start;
    dns_bucket *curr = prev->next;

    while (start != curr) {
        if (strcmp(curr->entry.domain, domain) == 0) { // Is actually in table
            prev->next = curr->next;
            free(curr);
            return 0;
        }
        curr = prev->next;
    }
    return -1; // Never found in table
}

// DNS table cleanup
void clean_table(bool shutdown) {
    dns_bucket *start = domain_table[0];
    dns_bucket *prev = start;
    dns_bucket *curr = prev->next;

    if (shutdown) { // Then we free everything in the table to avoid memory leaks
        while (start != curr) {
            prev->next = curr->next;
            free(curr);
            curr = prev->next;
        }
        free(curr);
    }
    else { // Then this is a routine cleaning for expired DNS table entries
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
}

int get_domain(dns_entry *map, int offset, unsigned char *buffer, bool notAuthority) {
    unsigned long index = get_hash(map->domain);
    while (domain_table[index]) {
        if ((strlen(domain_table[index]->entry.domain) == strlen(map->domain)) &&
            (strncmp(map->domain, domain_table[index]->entry.domain, strlen(map->domain)) == 0)) {
            
            // We found the Domain Name in the table so copy its entry and return
            memcpy(map, &domain_table[index]->entry, sizeof(dns_entry));
            return 0;
        }
        index++;
    }

    append_ln_to_log_file_dns_verbose("Not found in table...\n");

    // If recursion is not desired
    // If authority
    if (!notAuthority) {
        return -2;
    }
    
    // If we reach this point we need to query upstream for the IP addresses
    append_ln_to_log_file_dns_verbose("Now sending upstream...\n");


    // Here is the socket setup for sending/receiving DNS queries to/from the internet

    int sock;
    struct sockaddr_in sock_addr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        append_ln_to_log_file_dns_verbose("socket-upstream");
        return -1;
    }

    // Might not need because it might be default, but will leave for now to be safe
    struct ifreq myreqInt;
    memset(&myreqInt, 0, sizeof(myreqInt));
    strncpy(myreqInt.ifr_name, DEFAULT_WAN_IFACE, IFNAMSIZ);
    
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void *)&myreqInt, sizeof(myreqInt)) < 0) {
        append_ln_to_log_file_dns_verbose("setsockopt-upstream");
        close(sock);
        return -1;
    }

    // Bind on the local port and local address
    struct sockaddr_in local_saddr;
    memset(&local_saddr, 0, sizeof(local_saddr));
    local_saddr.sin_family = AF_INET;
    local_saddr.sin_port = htons(LOOKUP_PORT);
    local_saddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&local_saddr, sizeof(local_saddr)) < 0) {
        append_ln_to_log_file_dns_verbose("bind-upstream failed on port %d", LOOKUP_PORT);
        close(sock);
        return -1;
    }

    append_ln_to_log_file_dns_verbose("...This is DNS server running Upstream on port %d...\n\n", LOOKUP_PORT);

    // Connects the socket to the server’s IP address and port number
    memset((char *)&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(DNS_PORT);
    sock_addr.sin_addr.s_addr = dns_ip; // dns_ip already in network byte order

    if (connect(sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0)
    {
        append_ln_to_log_file_ntp("cannot connect upstream to %x\n", ntohl(dns_ip));
        close(sock);
        return time(NULL);
    }

    // Set a receive timeout so recv doesn't stall
    struct timeval utv;
    utv.tv_sec = 3;  // 3 seconds
    utv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&utv, sizeof(utv));

    // Setup Ends here


    int send_len, recv_len;
    if ((send_len = send(sock, buffer, offset, 0)) < 0) {
        append_ln_to_log_file_dns_verbose("sendto-upstream");
        close(sock);
        return -1;
    }
    append_ln_to_log_file_dns_verbose("Sent packet to upstream %s, port number:%d\n",
            inet_ntoa(sock_addr.sin_addr), ntohs(sock_addr.sin_port));

    // TODO: in case idk u can uncomment
    // memset(buffer, 0, offset);

    if ((recv_len = recv(sock, buffer, BUFFER_SIZE, 0)) < 0) {
        append_ln_to_log_file_dns_verbose("recv-upstream (fail or timeout)");
        close(sock);
        return -1;
    }

    append_ln_to_log_file_dns_verbose("Received packet from upstream %s, port number:%d\n",
            inet_ntoa(sock_addr.sin_addr), ntohs(sock_addr.sin_port));
    
    close(sock); // Made sure to close so we can use again

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
        append_ln_to_log_file_dns_verbose("not response upstream");
        return -1; 
    }

    if (hdr.rcd != 0) {
        append_ln_to_log_file_dns_verbose("error upstream");
        return -2; // must not be upstream then
    }

    // NOTE: I will return the map as the condensed CNAME chain
    // i.e. a.com -> b.com -> c.com -> 1.2.3.4 turns into a.com -> 1.2.3.4 for the client.
    // Trust that chain will be in orser

    // buffer[offset] should be the first byte of answers
    // answers:
    // first 2 bytes is ptr to domain name
    // then 2 bytes for type then 2 for class
    // 4 bytes for time ot live 
    // 2 bytes data length
    // 4 bytes for ip address (in order of normal bytes)

    int numAnsIp = 0;
    int temp = offset;
    unsigned char targetDomain[MAX_DN_LENGTH];
    memcpy(targetDomain, map->domain, MAX_DN_LENGTH);
    map->ttl = 0;
    for (int k = 0; k < hdr.numA; k++) {
        // identify the domain name for this entry
        unsigned char tempDomain[MAX_DN_LENGTH];
        memset(tempDomain, '\0', MAX_DN_LENGTH);
        process_domain(temp, buffer, tempDomain, 0); // Will find the domain name that is pointed to by the ptr to domain name
        if (strcmp(targetDomain, tempDomain) != 0) {
            append_ln_to_log_file_dns_verbose("cnames not in a chain not implemented"); // Still go through with returning the error dns header to the client
            return -1;
        }
        // identify the type of answer
        temp += 2;
        unsigned short typ = ntohs(*(unsigned short*)(buffer + temp));        
        // map->type = ntohs(*(unsigned short*)(buffer + temp));
        if (typ == 1) {
            // Then we know this is a A record so...
            temp += 4;
            map->ttl = ntohl(*(unsigned int*)(buffer + temp));
            temp += 6;
            for (int l = 0; l < IP_LENGTH; l++) {
                map->ip[numAnsIp][l] = buffer[temp + l];
            }
            temp += IP_LENGTH;
            numAnsIp++;
            if (numAnsIp == MAX_IPS) break;
        }
        else if (typ == 5) {
            // Then we know this is a CNAME so...
            temp += 8;
            int len = ntohs(*(unsigned short*)(buffer + temp));
            temp += 2;
            // Set it as our new target domain
            memset(targetDomain, '\0', MAX_DN_LENGTH);
            process_domain(temp, buffer, targetDomain, 0);
            temp += len;
        }
        else {
            // Not implemented type so will abandon rest of answers
            temp -= 2;
            append_ln_to_log_file_dns_verbose("non implemented error type"); // Still go through with returning the error dns header to the client
            break;
        }
        // *(unsigned int*)map->ip[k] = ntohl(*(unsigned int*)map->ip[k]); // So host byte order for insertion
    }
    
    // end TODO 

    if (map->ttl == 0) {
        append_ln_to_log_file_dns_verbose("No IPs in answer"); // Something is wrong there should be IPs at some point
        return -1;
    }
    
    index = insert_table(map->domain, map->ip, time(NULL) + map->ttl, numAnsIp);

    memcpy(map, &domain_table[index]->entry, sizeof(dns_entry));
    return 0;
}

int process_packet(dns_hdr *hdr, unsigned char *buffer) {
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

    // Erroneous query checking
    bool hasError = false;
    if (hdr->rcd != 0) {
        hdr->rcd = 4;
        append_ln_to_log_file_dns_verbose("query shouldn't have any errors");
        hasError = true; 
    }

    if (hdr->op != 0) {
        hdr->rcd = 4;
        append_ln_to_log_file_dns_verbose("only handle standard queries");
        hasError = true; 
    }

    if (hdr->z != 0) {
        hdr->rcd = 4;
        append_ln_to_log_file_dns_verbose("zero flag must be zero");
        hasError = true; 
    }

    if (hdr->qr != 0) {
        hdr->rcd = 4;
        append_ln_to_log_file_dns_verbose("not a query");
        hasError = true; 
    }

    if (hdr->numQ != 1) {
        hdr->rcd = 4;
        append_ln_to_log_file_dns_verbose("query must have one question");
        hasError = true; 
    }

    if (hdr->numA != 0) {
        hdr->rcd = 4;
        append_ln_to_log_file_dns_verbose("query must have no answer");
        hasError = true; 
    }

    if (hdr->auRR != 0) {
        hdr->rcd = 4;
        append_ln_to_log_file_dns_verbose("auth RR not allowed"); // Might change one to allow gotta look into
        hasError = true; 
    }

    if (hdr->adRR != 0) {
        hdr->rcd = 4;
        append_ln_to_log_file_dns_verbose("add RR not allowed"); // Might change one to allow gotta look into
        hasError = true; 
    }

    // If there are no errors with the incoming DNS query, we will handle it
    // Otherwise, we will return just the DNS header with Not Implemented RCODE 4
    int offset = !hasError ? process_query(hdr, buffer) : sizeof(dns_hdr);

    // If there was an error in process_query from get_domain
    if (offset == -1) {
        return -1;
    }
    // Or if the domain was not found
    if (offset == -2) {
        hdr->rcd = 2; // Server failure
        offset = sizeof(dns_hdr);
    }

    hdr->qr = 1;     // It is a response
    hdr->tc = 0;     // We never truncate
    hdr->ad = 0;     // We do not implement DNSSEC
    hdr->cd = 0;     // We do not implement DNSSEC
    hdr->ra = 1;     // Since if we do not have authority we ask another server

    *(unsigned short*)(buffer) = htons(hdr->id);        // id same
    flags = 0;                                            // Clear current flags
    flags |= (hdr->qr & 0x1) << 15;                        // reply = 1
    flags |= (hdr->op & 0xf) << 11;
    flags |= (hdr->aa & 0x1) << 10;
    flags |= (hdr->tc & 0x1) << 9;
    flags |= (hdr->rd & 0x1) << 8;                        
    flags |= (hdr->ra & 0x1) << 7;                        
    flags |= (hdr->z & 0x1) << 6;
    flags |= (hdr->ad & 0x1) << 5;
    flags |= (hdr->cd & 0x1) << 4;
    flags |= hdr->rcd & 0xf;                               
    *(unsigned short*)(buffer + 2) = htons(flags);
    *(unsigned short*)(buffer + 4) = htons(hdr->numQ);   // numQ same
    *(unsigned short*)(buffer + 6) = htons(hdr->numA);     // numA updates
    *(unsigned short*)(buffer + 8) = htons(hdr->auRR);     // Not implemented (hdr->auRR = 0)
    *(unsigned short*)(buffer + 10) = htons(hdr->adRR);    // Not implemented (hdr->adRR = 0)

    return offset;
}

int process_query(dns_hdr *hdr, unsigned char *buffer) {

    /* Process the data of DNS starting at buffer + sizeof(dns_hdr) */

    unsigned short offset = sizeof(dns_hdr);

    // For every requested domain name
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
    int ret = get_domain(&map, offset, buffer, hdr->rd);

    if (ret < 0) { // If there was an error (-1) or if the domain wasn't found (-2)
        return ret; 
    }

    hdr->aa = (map.ttl == LONG_MAX) ? 1 : 0; // Authoritative answer iff has LONG_MAX ttl since that means was added as an alias

    // TODO: Contruct answers here and store somewhere ill have to process all questions before putting at end of the buffer
    // After that we can do the next question

    // answers:
    // first 2 bytes is ptr to domain name
    // then 2 bytes for type then class
    // 4 bytes for time ot live 
    // 2 bytes data length
    // 4 bytes for ip address (in order of normal bytes)

    for (int j = 0; j < map.numIp; j++) {
        // We need to represent the domain name as pointer
        *(unsigned short*)(buffer + offset + (j * ANS_LENGTH)) = htons(domain_ptr);
        *(unsigned short*)(buffer + offset + (j * ANS_LENGTH) + 2) = htons(type);
        *(unsigned short*)(buffer + offset + (j * ANS_LENGTH) + 4) = htons(class);
        *(unsigned int*)(buffer + offset + (j * ANS_LENGTH) + 6) = htonl((unsigned int)(DEFAULT_SEND_TTL)); // Just give a default TTL for each so that it will refresh names like router if changed between router startups
        *(unsigned short*)(buffer + offset + (j * ANS_LENGTH) + 10) = htons(IP_LENGTH);
        for (int k = 0; k < IP_LENGTH; k++) {
            (buffer + offset + (j * ANS_LENGTH))[12 + k] = map.ip[j][k];
        }
    }
    hdr->numA = map.numIp;
    offset += hdr->numA * ANS_LENGTH;

    return (int) offset;
}
