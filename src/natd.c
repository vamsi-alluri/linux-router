// natd.c
#include "natd.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

void nat_main(int rx_fd, int tx_fd) {
    char buffer[256];
    ssize_t count;

    //pid_t pid = getpid();
    //write(tx_fd, &pid, sizeof(pid_t)); // Send the pid to be stored by the parent process.
    
    while ((count = read(rx_fd, buffer, sizeof(buffer))) > 0) {
        // Process command from router
        if (strcmp(buffer, "shutdown") == 0) break;
        
        // NAT implementation logic
        write(tx_fd, "NAT: Processed command\n", 24);
    }

    // Clean shutdown on EOF or explicit command
    write(tx_fd, "NAT: Shutting down\n", 19);
    close(rx_fd);
    close(tx_fd);
    exit(EXIT_SUCCESS);
}

