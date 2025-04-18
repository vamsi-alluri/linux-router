#ifndef DNSD_H
#define DNSD_H

typedef struct
{
    unsigned short id;            /* Transaction ID */
    unsigned short qr:1, op:4,      /* QR (query = 0, reply = 1), OPCODE (standard query = 0, inverse query = 1, server status request = 2) */
                   aa:1, tc:1,      /* Authoritative Answer (1 iff LAN domain name), TrunCation */
                   rd:1, ra:1,      /* Recursion Desired, Recursion Available */
                   z:1, ad:1,       /* Zero (always 0), Authentic Data (1 iff verified data) */
                   cd:1, rcd:4;     /* Checking Disabled, RCODE (no err = 0, format err = 1, server fail = 2, Nonexistent domain = 3) */
    unsigned short numQ;            /* Number of Questions */
    unsigned short numA;            /* Number of Answers */
    unsigned short auRR;            /* Number of Authority Resource Records */
    unsigned short adRR;            /* Number of Additional Resource Records */
} dns_hdr;

void dns_main(int rx_fd, int tx_fd);
// void shutdown(int rx_fd, int tx_fd);

#endif /* DNSD_H */
