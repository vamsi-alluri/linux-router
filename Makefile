# # Compiler and flags
# CC = gcc
# CFLAGS = -Wall -Wextra -O2

# # Directories
# SRC_DIR = src
# BIN_DIR = bin
# OBJ_DIR = obj

# # Source files
# ROUTER_SRC = $(SRC_DIR)/router.c
# DHCP_SRC = $(SRC_DIR)/dhcpd.c
# NAT_SRC = $(SRC_DIR)/natd.c
# DNS_SRC = $(SRC_DIR)/dnsd.c
# NTP_SRC = $(SRC_DIR)/ntpd.c

# # Object files
# ROUTER_OBJ = $(OBJ_DIR)/router.o
# DHCP_OBJ = $(OBJ_DIR)/dhcpd.o
# NAT_OBJ = $(OBJ_DIR)/natd.o
# DNS_OBJ = $(OBJ_DIR)/dnsd.o
# NTP_OBJ = $(OBJ_DIR)/ntpd.o

# HEADERS = $(SRC_DIR)/dhcpd.h $(SRC_DIR)/natd.h $(SRC_DIR)/dnsd.h $(SRC_DIR)/ntpd.h

# # Executables
# ROUTER_BIN = $(BIN_DIR)/router
# DHCP_BIN = $(BIN_DIR)/dhcpd
# NAT_BIN = $(BIN_DIR)/natd
# DNS_BIN = $(BIN_DIR)/dnsd
# NTP_BIN = $(BIN_DIR)/ntpd

# # Targets
# all: setup $(ROUTER_BIN) $(DHCP_BIN) $(NAT_BIN) $(DNS_BIN) $(NTP_BIN)

# setup:
# 	mkdir -p $(BIN_DIR) $(OBJ_DIR)

# $(ROUTER_BIN): $(ROUTER_OBJ)
# 	$(CC) -o $@ $^

# $(DHCP_BIN): $(DHCP_OBJ)
# 	$(CC) -o $@ $^

# $(NAT_BIN): $(NAT_OBJ)
# 	$(CC) -o $@ $^

# $(DNS_BIN): $(DNS_OBJ)
# 	$(CC) -o $@ $^

# $(NTP_BIN): $(NTP_OBJ)
# 	$(CC) -o $@ $^

# $(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
# 	$(CC) -c $< -o $@ $(CFLAGS)

# clean:
# 	rm -rf $(BIN_DIR) $(OBJ_DIR)

# .PHONY: all setup clean

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -g

# Directories
SRC_DIR = src
BIN_DIR = bin
OBJ_DIR = obj

# Source files and headers
ROUTER_SRC = $(SRC_DIR)/router.c $(SRC_DIR)/dhcpd.c $(SRC_DIR)/natd.c $(SRC_DIR)/dnsd.c $(SRC_DIR)/ntpd.c
HEADERS = $(SRC_DIR)/dhcpd.h $(SRC_DIR)/natd.h $(SRC_DIR)/dnsd.h $(SRC_DIR)/ntpd.h

# Object files and executable targets
ROUTER_OBJ = $(OBJ_DIR)/router.o $(OBJ_DIR)/dhcpd.o $(OBJ_DIR)/natd.o $(OBJ_DIR)/dnsd.o $(OBJ_DIR)/ntpd.o
ROUTER_BIN = $(BIN_DIR)/router

# Targets
all: setup $(ROUTER_BIN)

setup:
	mkdir -p $(BIN_DIR) $(OBJ_DIR)

$(ROUTER_BIN): $(ROUTER_OBJ)
	$(CC) -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR)

.PHONY: all setup clean
