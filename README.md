# debian-router

Capabilities: NAPT, DHCP, NTP, DNS, CLI Management App

### Instructions to run:
- `make` in the `linux-router/` directory, this will create executable binary file `router` in `/bin` and other object files in `/obj`.
- `./bin/router` starts the router
- - `./bin/router -v` For verbose mode to print debug messages.
 
### Note for using verbose mode: 
Use `print_verbose_ln` to print debug messages.


Architecture decided \[Updated over time, add/update as you please.\]:
For the sake of reusing, I'm naming the program that's gonna boot up services as `Router` 

- Router boots up DHCP, NAT, DNS, NTP and CLI. (Not yet sure if we need pipes for NTP.)
- Router program sets up the piping file descriptor for other programs to communicate.
- And it idles (Think if we could detact the processes from Router and end Router program.)

Things to read:
- Multi Threads and processes 
- Piping: for communication

Questions on exception handling:
- What happens if a thread fails, how to handle it?
