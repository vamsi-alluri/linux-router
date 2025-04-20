# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -g

# Directories
SRC_DIR = src
BIN_DIR = bin
OBJ_DIR = obj

# Source files and headers
ROUTER_SRC = $(SRC_DIR)/router.c $(SRC_DIR)/dhcpd.c $(SRC_DIR)/natd.c $(SRC_DIR)/dnsd.c $(SRC_DIR)/ntpd.c $(SRC_DIR)/packet_helper.c
HEADERS = $(SRC_DIR)/dhcpd.h $(SRC_DIR)/natd.h $(SRC_DIR)/dnsd.h $(SRC_DIR)/ntpd.h $(SRC_DIR)/packet_helper.h

# Object files and executable targets
ROUTER_OBJ = $(OBJ_DIR)/router.o $(OBJ_DIR)/dhcpd.o $(OBJ_DIR)/natd.o $(OBJ_DIR)/dnsd.o $(OBJ_DIR)/ntpd.o $(OBJ_DIR)/packet_helper.o
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
