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
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

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
    char name[5];
    void (* main_func)(int, int, int);
} service_t;

typedef struct {
    int service_id;
    char command[256];
} router_command;

void print_verboseln(char *message, ...);
void print_running_services(service_t *services);

/* ================= Process Creation ================= */
static void daemonize_process(int rx_fd, int tx_fd, char *argv[], const char *name) {
    // First fork to create background process
    pid_t first_pid = fork();
    if (first_pid < 0) {
        perror("fork");
        close(rx_fd); // Close pipes before exit
        close(tx_fd);
        exit(EXIT_FAILURE);
    }
    if (first_pid > 0) {
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

    prctl(PR_SET_NAME, name); // Set /proc/pid/comm name
    if (argv[0]) { // Overwrite argv[0] for ps/top visibility
        strncpy(argv[0], name, 4);
        argv[0][4] = '\0';
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

void start_service(service_t *svc, char *argv[]) {
    void (*entry)(int, int, int) = svc->main_func;
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

        daemonize_process(svc->router_to_svc[0], svc->svc_to_router[1], argv, svc->name);
        
        // Notify router we're ready
        // write(svc->svc_to_router[1], SERVICE_READY_MSG, sizeof(SERVICE_READY_MSG));
        
        entry(svc->router_to_svc[0], svc->svc_to_router[1], verbose);
        
        
        close(svc->router_to_svc[0]); // Close pipes before exit
        close(svc->svc_to_router[1]);
        exit(EXIT_FAILURE);           // If it reaches this point it should be a failure
    } 
    else { // Router process
        close(svc->router_to_svc[0]); // Close unused pipes
        close(svc->svc_to_router[1]);

        // Wait for service to return its PID
        pid_t child_pid;
        if (read(svc->svc_to_router[0], &child_pid, sizeof(pid_t)) > 0) {
            svc->running = true;
            svc->pid = child_pid;
            printf("Service %s (PID %d) started\n", svc->name, svc->pid);
        }
    }
}

/* ================= Signal Handling & Cleanup ================= */
void confirm_before_shutdown(){
    fprintf(stderr, "\n!!!CAUTION!!!\nShuts down all services.\n\nAre you sure? (y): ");
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
    else{           // Shutdowns without confirmation while testing. TODO: Remove this after development.
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

// This function shows the process as running and the next process as dead.
bool is_service_running(service_t *svc) {
    // print_verboseln("is_service_running pid: %d", svc->pid);
    if ((svc->pid) > 0){
        // Kill 0 returns 0 if the process is running.
        int result_from_kill = kill((svc->pid), 0); 
        // print_verboseln("Result from kill: %d", result_from_kill);
        return !result_from_kill;
    }
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


void print_help(service_t *services)
{
    fprintf(stderr, "Available commands:\n");
    fprintf(stderr, "  <service>:<command> - Send command to specific service\n");
    fprintf(stderr, "      <service>:start      - Start the specific service\n");
    fprintf(stderr, "      <service>:shutdown   - Shutdown the specific service\n");
    fprintf(stderr, "  config_lan <iface> <ip> <netmask> - Configure LAN interface\n");
    fprintf(stderr, "  help                - Show this help\n");
    fprintf(stderr, "  q                   - Shutdown router and all sub services.\n");
    fprintf(stderr, "  services            - Print what services are running.\n");
}

void print_running_services(service_t *services)
{
    fprintf(stderr, "Available services:\n");
    if (verbose == 1)
    {
        for (int i = 0; i < NUM_SERVICES; i++)
        {
            fprintf(stderr, "  %-5s - %s\n", SERVICE_NAMES[i], is_service_running(&services[i]) ? "running" : "not running");
        }
    }
    else
    {
        for (int i = 0; i < NUM_SERVICES; i++)
        {
            fprintf(stderr, "  %-5s - %s\n", SERVICE_NAMES[i], is_service_running(&services[i]) ? "running" : "not running");
        }
    }
}


/* ================= Network Configuration ================= */
// This function configures the LAN interface with a static IP address and netmask.
void configure_lan_interface(const char *iface_name, const char *ip_addr, const char *netmask) {
    int fd;
    struct ifreq ifr;
    struct sockaddr_in *addr;

    // Create a socket to perform ioctl calls
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Bring interface up
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
        perror("SIOCGIFFLAGS");
        close(fd);
        exit(EXIT_FAILURE);
    }
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
        perror("SIOCSIFFLAGS");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Set IP address
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ-1);
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    // Use the provided ip_addr argument
    if (inet_pton(AF_INET, ip_addr, &addr->sin_addr) <= 0) {
        fprintf(stderr, "Error: Invalid IP address format '%s'\n", ip_addr);
        close(fd);
        exit(EXIT_FAILURE);
    }

    if (ioctl(fd, SIOCSIFADDR, &ifr) == -1) {
        perror("SIOCSIFADDR");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Set netmask
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ-1);
    addr = (struct sockaddr_in *)&ifr.ifr_netmask; // Use ifr_netmask here
    addr->sin_family = AF_INET;
    // Use the provided netmask argument
    if (inet_pton(AF_INET, netmask, &addr->sin_addr) <= 0) {
        fprintf(stderr, "Error: Invalid netmask format '%s'\n", netmask);
        close(fd);
        exit(EXIT_FAILURE);
    }

    if (ioctl(fd, SIOCSIFNETMASK, &ifr) == -1) {
        perror("SIOCSIFNETMASK");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
    fprintf(stderr, "Successfully configured %s with %s/%s\n", iface_name, ip_addr, netmask);
}

/* ================= Command Handling ================= */
void handle_service_response(int service_id, int fd) {
    char buffer[256];
    ssize_t count = read(fd, buffer, sizeof(buffer));
    if (count > 0) {
        
        fprintf(stderr, "\33[2K\r");
        fprintf(stderr, "[Service %d] %.*s", service_id, (int)count, buffer);
        fprintf(stderr, "\nroot@router# ");
    }
    
}

void handle_cli_input(service_t *services, char * argv[]) {
    char raw_cmd[256];

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
            fprintf(stderr, "root@router# ");       // This is printed after waiting for input.
            return;
        }

        cmd.service_id = found;
        strncpy(cmd.command, command, sizeof(cmd.command)-1);

        if (cmd.service_id >= 0 && cmd.service_id < NUM_SERVICES) {
            if (strcmp(cmd.command, "start") == 0) {
                if (services[cmd.service_id].running) {
                    fprintf(stderr, "Error: %s service is already running\n", SERVICE_NAMES[cmd.service_id]);
                } else {
                    start_service(&services[cmd.service_id], argv);
                }
            } else if (services[cmd.service_id].running) {
                write(services[cmd.service_id].router_to_svc[1], cmd.command, strlen(cmd.command)+1);
                //fprintf(stderr, "Command sent to %s service. PID: %d\n", SERVICE_NAMES[cmd.service_id], services[cmd.service_id].pid);
            } else {
                fprintf(stderr, "Error: %s service is not running\n", SERVICE_NAMES[cmd.service_id]);
            }
        }
    } 
    else {
        // Commands to router: Handle all the commands locally.
        if (strcmp(raw_cmd, "q") == 0) {
            confirm_before_shutdown();
        } 
        else if (strcmp(raw_cmd, "help") == 0) {
            print_help(services);
            fprintf(stderr, "root@router# ");       // This is printed after waiting for input.
            return;
        } 
        else if (strcmp(raw_cmd, "") == 0){
            fprintf(stderr, "root@router# ");       // This is printed after waiting for input.
            return;                         // For an empty line or a return when no command is recognized.
        } 
        else if (strcmp(raw_cmd, "services") == 0) {
            // Print what services are running
            print_running_services(services);
            fprintf(stderr, "root@router# "); 
            return;
        }
        else if (strncmp(raw_cmd, "config_lan ", 11) == 0) {
            char *args = raw_cmd + 11; // point past "config_lan"
            char *iface = strtok(args, " ");
            char *ip = strtok(NULL, " ");
            char *mask = strtok(NULL, " ");

            if (iface && ip && mask) {
                configure_lan_interface(iface, ip, mask);
            } else {
                fprintf(stderr, "Usage: config_lan <interface> <ip_address> <netmask>\n");
            }
        }
        else {
            fprintf(stderr, "Unknown router command: '%s'\n", raw_cmd);
            print_help(services);
        }
    }
    fprintf(stderr, "root@router# ");       // This is printed after waiting for input.
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

    // Configure the LAN interface with a static IP address and netmask
    // Warning!: This is a placeholder. 
    // You should replace "enp0s8" with your actual interface name.
    //configure_lan_interface("enp0s8", "192.168.10.1", "255.255.255.0");

    // Create the services list struct
    service_t services[NUM_SERVICES] = {0};
    void (*entries[4])(int, int, int) = {dhcp_main, nat_main, dns_main, ntp_main};
    register_signal_handlers();

    // Start all services
    for (int i = 0; i < NUM_SERVICES; i++) {
        service_t *service_selected = &services[i];
        strncpy(service_selected->name, SERVICE_NAMES[i], 4);
        (service_selected->name)[4] = '\0';
        service_selected->main_func = entries[i];
        start_service(service_selected, argv);
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

        for (int i = 0; i < NUM_SERVICES; i++) {
            if (services[i].running && FD_ISSET(services[i].svc_to_router[0], &readfds)) {
                handle_service_response(i, services[i].svc_to_router[0]);
                services[i].running = is_service_running(&services[i]);
            }
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            handle_cli_input(services, argv);
        }
    }

    // Cleanup and exit - when the command is quit or shutdown.
    cleanup_services(services);
    printf("\nRouter shutdown complete\n");
    return EXIT_SUCCESS;
}
