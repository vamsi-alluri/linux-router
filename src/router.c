#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>

// Service headers
#include "dhcpd.h"
#include "natd.h"
#include "dnsd.h"
#include "ntpd.h"

/* ================= Globals ================= */
#define NUM_SERVICES 4
#define SERVICE_READY_MSG "READY"

int verbose = 0;
char *progname;
const char *SERVICE_NAMES[NUM_SERVICES] = {"dhcp", "nat", "dns", "ntp"};
volatile sig_atomic_t shutdown_requested_flag = 0;

typedef struct {
    pid_t pid;
    int router_to_svc[2];
    int svc_to_router[2];
    bool running;
} service_t;

typedef struct {
    int service_id;
    char command[256];
} router_command;

void print_verboseln(char *message, ...);

/* ================= Process Creation ================= */
static void daemonize_process(int rx_fd, int tx_fd) {
    // First fork to create background process
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(rx_fd); // Close pipes before exit
        close(tx_fd);
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        close(rx_fd); // Close pipes before exit
        close(tx_fd);
        exit(EXIT_SUCCESS); // Parent exits
    }

    // Create new session and process group
    if (setsid() < 0) {
        perror("setsid");
        close(rx_fd); // Close pipes before exit
        close(tx_fd);
        exit(EXIT_FAILURE);
    }

    // Second fork to ensure no terminal association
    pid = fork();
    if (pid < 0) {
        perror("fork");
        close(rx_fd); // Close pipes before exit
        close(tx_fd);
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        close(rx_fd); // Close pipes before exit
        close(tx_fd);
        exit(EXIT_SUCCESS); // Parent exits
    }

    // Set file permissions
    umask(0);
    chdir("/");

    // Close all inherited file descriptors except our pipes
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        if (x != rx_fd && x != tx_fd) close(x);
    }

    // Reopen standard file descriptors to /dev/null
    open("/dev/null", O_RDWR); // stdin
    dup(0); // stdout
    dup(0); // stderr
}

void start_service(service_t *svc, void (*entry)(int, int)) {
    // Create communication pipes
    if (pipe(svc->router_to_svc) == -1 || pipe(svc->svc_to_router) == -1) {
        perror("pipe");
        exit(EXIT_FAILURE);
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(svc->router_to_svc[0]); // Close pipes before exit
        close(svc->router_to_svc[1]);
        close(svc->svc_to_router[0]);
        close(svc->svc_to_router[1]);
        exit(EXIT_FAILURE);
    }

    if (pid == 0) { // Service process
        close(svc->router_to_svc[1]); // Close unused pipes
        close(svc->svc_to_router[0]);

        daemonize_process(svc->router_to_svc[0], svc->svc_to_router[1]);
        
        // Notify router we're ready
        write(svc->svc_to_router[1], SERVICE_READY_MSG, sizeof(SERVICE_READY_MSG));
        
        entry(svc->router_to_svc[0], svc->svc_to_router[1]);
        
        close(svc->router_to_svc[0]); // Close pipes before exit
        close(svc->svc_to_router[1]);

        exit(EXIT_SUCCESS);
    } 
    else { // Router process
        close(svc->router_to_svc[0]); // Close unused pipes
        close(svc->svc_to_router[1]);

        // Wait for service ready signal
        char buf[sizeof(SERVICE_READY_MSG)];
        if (read(svc->svc_to_router[0], buf, sizeof(buf)) > 0) {
            svc->running = true;
            svc->pid = pid - 1;     // TODO: Have to figure out why we've to decrement 1 to the assigned pid.'.
            printf("Service (PID %d) started\n", svc->pid);
        }
    }
}

/* ================= Signal Handling & Cleanup ================= */
void confirm_before_shutdown(){
    fprintf(stderr, "\n!!!CAUTION!!!\nShuts down all services.\n\nAre you sure? (y):");
    char test_y_n = getchar();
    if ('y' == test_y_n || 'Y' == test_y_n){
        shutdown_requested_flag = 1;
    }
    return;
}

void sigint_handler(int sig) {
    if (verbose == 0){
        confirm_before_shutdown();
    }
    else{           // Shutdowns without confirmation while testing.
        shutdown_requested_flag = 1;
    }
}

void register_signal_handlers() {
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

void cleanup_services(service_t *services) {
    for (int i = 0; i < NUM_SERVICES; i++) {
        if (services[i].running) {
            // Close router's write end to send EOF
            close(services[i].router_to_svc[1]);
            
            // Close router's read end
            close(services[i].svc_to_router[0]);
        }
    }
    
    // Wait for services to exit
    int status;
    for (int i = 0; i < NUM_SERVICES; i++) {
        if (services[i].running) {
            waitpid(services[i].pid, &status, 0);
            printf("Service %d exited\n", i);
        }
    }
}

// TODO: This is NOT WORKING
// Testcase: kill a specific process using <service>:shutdown, and check the running services.
// This function shows the process as running and the next process as dead.
bool is_service_running(service_t *svc) {
    print_verboseln("is_service_running pid: %d", svc->pid);
    if ((svc->pid) > 0){
        // Kill 0 returns 0 if the process is running.
        int result_from_kill = kill((svc->pid), 0); 
        print_verboseln("Result from kill: %d", result_from_kill);
        return !result_from_kill;
    }
    else
        return false;
}

/* ================= Debug Messages ================= */
void print_hex_ln(const char *message, unsigned char *data, int length) {
    if (verbose == 1){
        int i;
        fprintf(stderr, "XXXX %s", message);
        for(i=0; i<length; i++) {
        if(i%16 == 0) {
            fprintf(stderr, "\n");
        }
        fprintf(stderr, "%02x ", data[i]);
        }
        fprintf(stderr, "\n");
    }
}

// Prints anything you pass into stderr for faster flushing.
void print_verboseln(char *message, ...){
    if (verbose == 1){
      va_list argp;
      
      va_start(argp, message);
      fprintf(stderr, "[debug]");
      vfprintf(stderr, message, argp);
      vfprintf(stderr, "\n", argp);
      va_end(argp);
    }
}

void print_help(service_t *services){
    fprintf(stderr, "Available commands:\n");
    fprintf(stderr, "  <service>:<command> - Send command to specific service\n");
    fprintf(stderr, "  help                - Show this help\n");
    fprintf(stderr, "  q                   - Shutdown router and all sub services.\n");
    fprintf(stderr, "Available services:\n");
    if (verbose == 1){
        for (int i = 0; i < NUM_SERVICES; i++) {
            fprintf(stderr, "  %-5s - %s\n", SERVICE_NAMES[i], is_service_running(&services[i]) ? "running" : "not running");
        }
    }
    else{
        for (int i = 0; i < NUM_SERVICES; i++) {
            fprintf(stderr, "  %-5s - %s\n", SERVICE_NAMES[i], is_service_running(&services[i]) ? "running" : "not running");
        }
    }
    fprintf(stderr, "\nroot@router# ");

}

/* ================= Command Handling ================= */
void handle_service_response(int service_id, int fd) {
    char buffer[256];
    ssize_t count = read(fd, buffer, sizeof(buffer));
    if (count > 0) {
        printf("[Service %d] %.*s\n", service_id, (int)count, buffer);
        fprintf(stderr, "\nroot@router# ");
    }
}

void handle_cli_input(service_t *services) {
    char raw_cmd[256];
    fprintf(stderr, "root@router# ");       // This is printed after waiting for input.

    if (!fgets(raw_cmd, sizeof(raw_cmd), stdin)) return;

    // Trim newline
    raw_cmd[strcspn(raw_cmd, "\n")] = 0;

    router_command cmd = {0};
    char *delim = strchr(raw_cmd, ':');
    
    if (delim) {
        // Delimiter present: Direct command to specific service.
        *delim = '\0';
        char *service_name = raw_cmd;
        char *command = delim + 1;

        // Find service ID by name
        int found = -1;
        for (int i = 0; i < NUM_SERVICES; i++) {
            if (strcmp(service_name, SERVICE_NAMES[i]) == 0) {
                found = i;
                break;
            }
        }

        if (found == -1) {
            fprintf(stderr, "Invalid service name. Available services:\n");
            for (int i = 0; i < NUM_SERVICES; i++) {
                fprintf(stderr, " - %s\n", SERVICE_NAMES[i]);
            }
            return;
        }

        cmd.service_id = found;
        strncpy(cmd.command, command, sizeof(cmd.command)-1);

        if (cmd.service_id >= 0 && cmd.service_id < NUM_SERVICES) {
            if (services[cmd.service_id].running) {
                write(services[cmd.service_id].router_to_svc[1], cmd.command, strlen(cmd.command)+1);
                fprintf(stderr, "Command sent to %s service\n", SERVICE_NAMES[cmd.service_id]);
            } else {
                fprintf(stderr, "Error: %s service is not running\n", SERVICE_NAMES[cmd.service_id]);
            }
        }
    } 
    else {
        // Commands to router: Handle all the commands locally.
        if (strcmp(raw_cmd, "q") == 0) {
            confirm_before_shutdown();
        } else if (strcmp(raw_cmd, "help") == 0) {
            print_help(services);
            return;
        }
        else if (strcmp(raw_cmd, "") == 0){
            return;                         // For an empty line or a return when no command is recognized.
        } 
        else {
            fprintf(stderr, "Unknown router command: '%s'\n", raw_cmd);
            print_help(services);
        }
    }
}

/* ================= Main Application ================= */
int main(int argc, char *argv[]) {
    progname = argv[0];
    
    int option;

    if (argc > 1){    
        fprintf(stderr, "Got more arguments %s\n", argv[1]);
        while((option = getopt(argc, argv, "v")) != -1){
            switch(option) {
                case 'v':
                    verbose = 1;
                    print_verboseln("Verbose mode enabled.");
                    break;
                default:
                    fprintf(stderr, "Default option.\n");
                    break;
            }
        }
    }

    service_t services[NUM_SERVICES] = {0};
    register_signal_handlers();

    // Start all services
    for (int i = 0; i < NUM_SERVICES; i++) {
        void (*entries[4])(int, int) = {dhcp_main, nat_main, dns_main, ntp_main};
        start_service(&services[i], entries[i]);
    }
    
    fprintf(stderr, "root@router# ");

    // Main event loop
    while (!shutdown_requested_flag) {
        
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);

        int max_fd = STDIN_FILENO;
        for (int i = 0; i < NUM_SERVICES; i++) {
            if (services[i].running) {
                FD_SET(services[i].svc_to_router[0], &readfds);
                if (services[i].svc_to_router[0] > max_fd) {
                    max_fd = services[i].svc_to_router[0];
                }
            }
        }

        int ready = select(max_fd + 1, &readfds, NULL, NULL, NULL);
        if (ready == -1) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            handle_cli_input(services);
        }

        for (int i = 0; i < NUM_SERVICES; i++) {
            if (services[i].running && FD_ISSET(services[i].svc_to_router[0], &readfds)) {
                handle_service_response(i, services[i].svc_to_router[0]);
            }
        }
    }

    // Cleanup and exit - when the command is quit or shutdown.
    cleanup_services(services);
    printf("\nRouter shutdown complete\n");
    return EXIT_SUCCESS;
}
