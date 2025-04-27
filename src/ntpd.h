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

static time_t last_refresh;
static int refresh_interval;

void ntp_main(int rx_fd, int tx_fd);
time_t refresh_time();
void handle_command(int rx_fd, int tx_fd, char *command);

#endif /* NTPD_H */
