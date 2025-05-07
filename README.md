# linux-router

Capabilities: NAPT, DHCP, NTP, DNS, CLI Management App

### Instructions to run:
- `make` in the `linux-router/` directory, this will create executable binary file `router` in `/bin` and other object files in `/obj`.
- `./bin/router` starts the router
- - `./bin/router -v` For verbose mode to print debug messages.
 
### Note for using verbose mode: 
Use `print_verbose_ln` to print debug messages.

Commands:
<service name>:<command>
- `nat:start` - Starts the NAT service.
- `nat:shutdown` - Shuts down the NAT service.
- `nat:entries` - Displays the the current entries in the NAT table.
- `nat:cleanup entries` - Clear the timeout entries in the NAT table.
- `nat:clear` - Clears all the entries in the NAT table.
- `nat:arp cache` - Displays the current ARP cache.
- `nat:clear arp cache` - Clears the ARP cache.
- `nat:clear logs` - Clears the log files.

- `dhcp:start` - Starts the DHCP service.
- `dhcp:shutdown` - Shuts down the DHCP service.
- `dhcp:list_leases` - Displays the current leases in the DHCP server.
- `dhcp:status` - Displays the active leases and active threads.

- `dns:start` - Starts the DNS service.
- `dns:shutdown` - Shuts down the DNS service.
- `dns:clean` - Cleans the DNS cache.
- `dns:set <Domain Name> <IPv4 Address>` - Sets the DNS entry for the specified domain name to the specified IPv4 address.
- `dns:unset <Domain Name>` - Unsets the DNS entry for the specified domain name.
- `dns:upstream <IPv4 Address>` - Sets the upstream DNS server to the specified IPv4 address.
- `dns:table` - Displays the current DNS table.

- `ntp:start` - Starts the NTP service.
- `ntp:shutdown` - Shuts down the NTP service.
- `ntp:server <server ip/domain address>` - Sets the specified server as the NTP server.
- `ntp:interval <number in seconds>` - Sets the interval for NTP synchronization.
- `ntp:refresh` - forces a refresh of the NTP time from the set NTP server.

### DHCP Implementation:
The router includes a full-featured DHCP server with the following capabilities:
- Automatic IP address allocation from configurable subnet (default 192.168.10.0/24)
- Support for all standard DHCP message types (DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE)
- Lease management with configurable lease time
- Concurrent request handling using multi-threading
- Thread-safe operations with mutex protection

#### DHCP CLI Commands:
- `status` - Shows current DHCP server status including active leases and threads
- `list_leases` - Displays all active DHCP leases with IP, MAC, and expiration time
- `shutdown` - Gracefully terminates the DHCP service

### NAT - Network Address and Port Translation

Implemented in `napt.c`, `napt.h` with helper files `napt_helper.c`, `napt_helper.h`.

**Definitions:**
- Inbound: Traffic coming from the internet to the local network.
- Outbound: Traffic going from the local network to the internet.

## NTP:
In order for the NTP time syncronization to be done exclusively by the NTP server, you must run this code to disable the `systemd-timesyncd` process that will automatically do NTP syncronization as a built in part of Debian OS: `sudo systemctl stop systemd-timesyncd`, `sudo systemctl disable systemd-timesyncd`, `sudo systemctl mask systemd-timesyncd`. You can check if it is running before and after with `sudo systemctl status systemd-timesyncd`.

Also in the client, run `sudo vim /etc/systemd/timesyncd.conf`, add the line `NTP=router` so that only the router's NTP server is contacted, and `sudo systemctl restart systemd-timesyncd` to restart the clients built in NTP.


Architecture:
For the sake of reusing, I'm naming the program that's gonna boot up services as `Router` 

- Router boots up DHCP, NAT, DNS, and NTP as daemons.
- Router program acts as CLI
- It sets up the piping file descriptor for other programs to communicate.
- And it idles as a cli program to manage the daemons.

Things to read:
- Multi Threads and processes 
- Piping: for communication

Questions on exception handling:
- What happens if a thread fails, how to handle it?

## Notes from development:
Due to the main router function requirements, the main function of each service exlcuding the router main function must write its pid back to the router main function, so as to both update the router main function that the service has started and to get its pid for accurate shutdown.

If you are planning to add a router specific command that is not in relation to a service, make sure you add it to the help print.
