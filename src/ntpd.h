#ifndef NTPD_H
#define NTPD_H

typedef struct
{
    unsigned char li:2, vn:3, mode:3;      /* Leap Indicator (no warning = 0), Version Number (4), Mode (Server = 4) */
    unsigned char strat;                   /* Stratum (Secondary Server = 2-15) */
    unsigned char poll;                    /* Poll */
    unsigned char prec;                    /* Precision */
    unsigned int rtDly;                    /* Root Delay */
    unsigned int rtDsp;                    /* Root Dispersion */
    unsigned int id;                       /* Reference ID */
    unsigned long ref;                     /* Reference Timestamp */
    unsigned long org;                     /* Origin Timestamp */
    unsigned long rec;                     /* Receive Timestamp */
    unsigned long xmt;                     /* Transmit Timestamp */
} ntp_packet;


// typedef struct {
//     unsigned char dst[6];
//     unsigned char src[6];
//     short type;
// } ethhdr;

// typedef struct {
//     unsigned char len:4, var:4;
//     unsigned char ser;
//     unsigned short tot;
//     unsigned short ide;
//     unsigned short flg:3, frg:13;
//     unsigned char tml;
//     unsigned char ptc;
//     unsigned short chk;
//     unsigned int src;
//     unsigned int dst;
// } iphdr;

// typedef struct {
//     unsigned short src;
//     unsigned short dst;
//     unsigned int sqn;
//     unsigned int akn;
//     unsigned short hrz:4, len:4, fin:1, syn:1, rst:1, psh:1, 
//                     ack:1, urg:1, ece:1, cwr:1;
//     unsigned short win;
//     unsigned short chk;
//     unsigned short upt;
// } tcphdr;

// typedef struct {
//     unsigned short src;
//     unsigned short dst;
//     unsigned short len;
//     unsigned short sum;
// } udphdr;


void ntp_main(int rx_fd, int tx_fd);
// void shutdown(int rx_fd, int tx_fd);

#endif /* NTPD_H */
