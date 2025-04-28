#ifndef NTPD_H
#define NTPD_H

#include <time.h>
#include <stdarg.h>
typedef struct
{
    unsigned char li_vn_mode;              /* Leap Indicator (no warning = 0), Version Number (4), Mode (Server = 4) */
    unsigned char strat;                   /* Stratum (Secondary Server = 2-15) */
    unsigned char poll;                    /* Poll */
    unsigned char prec;                    /* Precision */
    unsigned int rtDly;                    /* Root Delay */
    unsigned int rtDsp;                    /* Root Dispersion */
    unsigned int id;                       /* Reference ID */
    unsigned int refSec;                   /* Reference Timestamp in Seconds */
    unsigned int refFrc;                   /* Reference Timestamp in Fractions of a Second */
    unsigned int orgSec;                   /* Origin Timestamp in Seconds */
    unsigned int orgFrc;                   /* Origin Timestamp in Fractions of a Second */
    unsigned int recSec;                   /* Receive Timestamp in Seconds */
    unsigned int recFrc;                   /* Receive Timestamp in Fractions of a Second */
    unsigned int xmtSec;                   /* Transmit Timestamp in Seconds */
    unsigned int xmtFrc;                   /* Transmit Timestamp in Fractions of a Second */
} ntp_packet;

static time_t last_refresh;
static int refresh_interval;

void ntp_main(int rx_fd, int tx_fd, int verbose, char * parent_dir);
time_t refresh_time();
void handle_ntp_command(int rx_fd, int tx_fd, unsigned char *command);
void append_ln_to_log_file_ntp(const char *msg, ...);
void append_ln_to_log_file_ntp_verbose(const char *msg, ...);
static void vappend_ln_to_log_file_ntp(const char *msg, va_list args);
static void clear_log_file_ntp();

#endif /* NTPD_H */
