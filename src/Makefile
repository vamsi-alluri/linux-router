CC     = gcc
CFLAGS = -Wall -Wextra -g -I.
LDFLAGS_SERVER = -lpthread

all: dhcp_server dhcp_client

dhcp_server: dhcp_server.o
	$(CC) $(CFLAGS) -o dhcp_server dhcp_server.o $(LDFLAGS_SERVER)

dhcp_client: dhcp_client.o
	$(CC) $(CFLAGS) -o dhcp_client dhcp_client.o

dhcp_server.o: dhcp_server.c dhcp.h
	$(CC) $(CFLAGS) -c dhcp_server.c

dhcp_client.o: dhcp_client.c dhcp.h
	$(CC) $(CFLAGS) -c dhcp_client.c

clean:
	rm -f dhcp_server dhcp_client *.o

.PHONY: all clean
