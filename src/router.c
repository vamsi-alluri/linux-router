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

// Service headers
#include "dhcpd.h"
#include "natd.h"
#include "dnsd.h"
#include "ntpd.h"

#define NUM_SERVICES 4
#define SERVICE_READY_MSG "READY"

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

const char *SERVICE_NAMES[NUM_SERVICES] = {"dhcp", "nat", "dns", "ntp"};

static void daemonize_process(int rx_fd, int tx_fd) {
    // First fork to create background process
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) exit(EXIT_SUCCESS); // Parent exits

    // Create new session and process group
    if (setsid() < 0) {
        perror("setsid");
        exit(EXIT_FAILURE);
    }

    // Second fork to ensure no terminal association
    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) exit(EXIT_SUCCESS); // Parent exits

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
        exit(EXIT_FAILURE);
    }

    if (pid == 0) { // Service process
        close(svc->router_to_svc[1]);
        close(svc->svc_to_router[0]);

        daemonize_process(svc->router_to_svc[0], svc->svc_to_router[1]);
        
        // Notify router we're ready
        write(svc->svc_to_router[1], SERVICE_READY_MSG, sizeof(SERVICE_READY_MSG));
        
        entry(svc->router_to_svc[0], svc->svc_to_router[1]);
        exit(EXIT_SUCCESS);
    } 
    else { // Router process
        close(svc->router_to_svc[0]);
        close(svc->svc_to_router[1]);

        // Wait for service ready signal
        char buf[sizeof(SERVICE_READY_MSG)];
        if (read(svc->svc_to_router[0], buf, sizeof(buf)) > 0) {
            svc->running = true;
            printf("Service (PID %d) started\n", pid);
        }
    }
}

/* ================= Signal Handling & Cleanup ================= */
volatile sig_atomic_t shutdown_requested = 0;

void sigint_handler(int sig) {
    shutdown_requested = 1;
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

void confirm_before_shutdown(){
    fprintf(stderr, "!!!CAUTION!!!\nShuts down all services.\n\nAre you sure? (y):");
    char test_y_n = getchar();
    if ('y' == test_y_n || 'Y' == test_y_n){
        shutdown_requested = 1;
    }
    return;
}

/* ================= Command Handling ================= */
void handle_service_response(int service_id, int fd) {
    char buffer[256];
    ssize_t count = read(fd, buffer, sizeof(buffer));
    if (count > 0) {
        printf("[Service %d] %.*s", service_id, (int)count, buffer);
    }
}

// TODO: Have to handle first root@router# print.
void handle_cli_input(service_t *services) {
    char raw_cmd[256];
    // fprintf(stderr, "root@router# ");
    printf("root@router# "); 
    fflush(stdout);
    if (!fgets(raw_cmd, sizeof(raw_cmd), stdin)) return;

    // Trim newline
    raw_cmd[strcspn(raw_cmd, "\n")] = 0;

    router_command cmd = {0};
    char *delim = strchr(raw_cmd, ':');
    
    if (delim) {
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
                write(services[cmd.service_id].router_to_svc[1], 
                     cmd.command, strlen(cmd.command)+1);
                fprintf(stderr, "Command sent to %s service\n", SERVICE_NAMES[cmd.service_id]);
            } else {
                fprintf(stderr, "Error: %s service is not running\n", SERVICE_NAMES[cmd.service_id]);
            }
        }
    } else {
        // Handle all the commands.
        if (strcmp(raw_cmd, "q") == 0) {
            confirm_before_shutdown();
        } else if (strcmp(raw_cmd, "help") == 0) {
            fprintf(stderr, "Available commands:\n");
            fprintf(stderr, "  <service>:<command> - Send command to specific service\n");
            fprintf(stderr, "  help                - Show this help\n");
            fprintf(stderr, "  q                   - Shutdown router and all sub services.\n");
            fprintf(stderr, "Available services:\n");
            for (int i = 0; i < NUM_SERVICES; i++) {
                fprintf(stderr, "  %-5s - %s\n", SERVICE_NAMES[i], 
                        services[i].running ? "running" : "not running");
            }
        }
        else if (strcmp(raw_cmd, "") == 0){
            return;
        } 
        else {
            fprintf(stderr, "Unknown router command: '%s'\n", raw_cmd);
        }
    }
}

/* ================= Main Application ================= */
int main() {
    service_t services[NUM_SERVICES] = {0};
    register_signal_handlers();

    // Start all services
    void (*entries[NUM_SERVICES])(int, int) = {dhcp_main, nat_main, dns_main, ntp_main};
    for (int i = 0; i < NUM_SERVICES; i++) {
        start_service(&services[i], entries[i]);
    }

    // Main event loop
    while (!shutdown_requested) {
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
