#include "dnsd.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

void dns_main(int rx_fd, int tx_fd){
    char buffer[256];
    ssize_t count;
    
    while ((count = read(rx_fd, buffer, sizeof(buffer))) > 0) {
        // Process command from router
        if (strcmp(buffer, "shutdown") == 0) break;
        
        // Implementation logic
        write(tx_fd, "DNS: Processed command\n", 24);
    }

    // Clean shutdown on EOF or explicit command
    write(tx_fd, "DNS: Shutting down\n", 19);
    close(rx_fd);
    close(tx_fd);
    exit(EXIT_SUCCESS);
}

