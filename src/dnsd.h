#ifndef DNSD_H
#define DNSD_H

#include <stdbool.h>
#define MAX_DN_LENGTH 255
#define IP_LENGTH 4          /* For IPv4 */
#define ANS_LENGTH 16        /* DNS answer */
#define MAX_IPS 3            
#define MAX_ENTRIES 256
#define DEFAULT_TTL 14400    /* 4 hours in seconds */
#define LOOKUP_IP 0x08080808     // Google DNS IPv4


typedef struct
{
    unsigned short id;              /* Transaction ID */
    unsigned short qr:1, op:4,      /* QR (query = 0, reply = 1), OPCODE (standard query = 0, inverse query = 1, server status request = 2) */
                   aa:1, tc:1,      /* Authoritative Answer (1 iff LAN domain name), TrunCation */
                   rd:1, ra:1,      /* Recursion Desired, Recursion Available */
                   z:1, ad:1,       /* Zero (always 0), Authentic Data (1 iff verified data) */
                   cd:1, rcd:4;     /* Checking Disabled, RCODE (no err = 0, format err = 1, serv fail = 2, Name err = 3, not implemented = 4, refused = 5) */
    unsigned short numQ;            /* Number of Questions */
    unsigned short numA;            /* Number of Answers */
    unsigned short auRR;            /* Number of Authority Resource Records (Not used so always 0) */
    unsigned short adRR;            /* Number of Additional Resource Records (Not used so always 0) */
} dns_hdr;

typedef struct
{
    unsigned char domain[MAX_DN_LENGTH];    /* Domain name (i.e. www.google.com) */
    unsigned char ip[MAX_IPS][IP_LENGTH];   /* Array of IP addresses (i.e. 8.8.8.8) */
    unsigned short numIp;                   /* Number of IP addresses in ip array */
    unsigned long ttl;                      /* Time that the entry will expire (default is 4 hours after no use) */
} dns_entry;

typedef struct
{
    dns_entry entry;                    /* Actual DNS Entry */
    struct dns_bucket *next;            /* Used for iterating through used elements of the domain table  */
} dns_bucket;

static dns_bucket *domain_table[MAX_ENTRIES];   /* Table contains pointers to buckets that contain the actual dns entry */
                                                /* and a pointer to the next dns entry in the table for navigation. */
static int lastIndex = 0;
static int dns_ip = LOOKUP_IP;          /* IP address for recursive DNS queries. Will be stored in network byte order */

void dns_main(int rx_fd, int tx_fd);
void handle_command(int rx_fd, int tx_fd, unsigned char  *command);
int process_domain(unsigned short offset, unsigned char  *buffer, unsigned char  *domain, int index);
unsigned long get_hash(unsigned char *domain);
unsigned long insert_table(unsigned char *domain, unsigned char **ip, int numIp, bool alias);
void clean_table(bool shutdown);
int get_domain(dns_entry *map, int offset, unsigned char  *buffer, bool authority);
int process_packet(dns_hdr *hdr, unsigned char  *buffer);
int process_query(dns_hdr *hdr, unsigned char  *buffer);

#endif /* DNSD_H */
