# linux-router

Capabilities: NAPT, DHCP, NTP, DNS, CLI Management App

### Instructions to run:
- `make` in the `linux-router/` directory, this will create executable binary file `router` in `/bin` and other object files in `/obj`.
- `./bin/router` starts the router
- - `./bin/router -v` For verbose mode to print debug messages.
 
### Note for using verbose mode: 
Use `print_verbose_ln` to print debug messages.


### NAT - Network Address and Port Translation

Implemented in `napt.c`, `napt.h` with helper files `napt_helper.c`, `napt_helper.h`.



## Available commands:
Additions Pending


## Configuration:

The configuration is flushed to disk on shut down or on a change to the configuration and is loaded from the file on boot.

`nat_config.ini` is at `<base directory>/nat/`.

Example configuration:
```
[global]
public_ip = 203.0.113.5
port_start = 60000
port_end = 65000
tcp_timeout = 60
udp_timeout = 5
icmp_timeout = 60
log_path = /var/log/natd.log
max_log_size = 10485760

[interfaces]
enp0s8 = lan
enp0s3 = wan

[static]
192.168.1.100:80 = 203.0.113.5:8080  # TCP
192.168.1.101:* = 203.0.113.5:*      # All ports
```


Architecture decided \[Updated over time, add/update as you please.\]:
For the sake of reusing, I'm naming the program that's gonna boot up services as `Router` 

- Router boots up DHCP, NAT, DNS, and NTP as daemons.
- Router program sets up the piping file descriptor for other programs to communicate.
- And it idles as a cli program to manage the daemons.

Things to read:
- Multi Threads and processes 
- Piping: for communication

Questions on exception handling:
- What happens if a thread fails, how to handle it?

## Notes from development:
Due to the main router function requirements, the main function of each service exlcuding the router main function must write its pid back to the router main function, so as to both update the router main function that the service has started and to get its pid for accurate shutdown.