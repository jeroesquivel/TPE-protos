CC = gcc
CFLAGS = -std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-variable -Wno-sign-compare -D_POSIX_C_SOURCE=200112L -g

ifeq ($(shell uname),Darwin)
    CFLAGS += -DMSG_NOSIGNAL=0
endif

LDFLAGS = -pthread

SRC_DIR = src
UTILS_DIR = $(SRC_DIR)/utils
SOCKS5_DIR = $(SRC_DIR)/socks5
AUTH_DIR = $(SRC_DIR)/auth
USERS_DIR = $(SRC_DIR)/users
METRICS_DIR = $(SRC_DIR)/metrics
ADMIN_DIR = $(SRC_DIR)/admin
DNS_DIR = $(SRC_DIR)/dns
BIN_DIR = .

UTILS_SRC = $(UTILS_DIR)/buffer.c $(UTILS_DIR)/selector.c $(UTILS_DIR)/stm.c \
            $(UTILS_DIR)/netutils.c $(UTILS_DIR)/parser.c $(UTILS_DIR)/parser_utils.c

SOCKS5_SRC = $(SOCKS5_DIR)/socks5.c $(SOCKS5_DIR)/handshake.c \
             $(SOCKS5_DIR)/request.c $(SOCKS5_DIR)/copy.c

AUTH_SRC = $(AUTH_DIR)/auth.c
USERS_SRC = $(USERS_DIR)/users.c
METRICS_SRC = $(METRICS_DIR)/metrics.c
ADMIN_SRC = $(ADMIN_DIR)/admin_server.c $(ADMIN_DIR)/admin_auth.c $(ADMIN_DIR)/admin_commands.c
DNS_SRC = $(DNS_DIR)/dns_resolver.c
MAIN_SRC = $(SRC_DIR)/main.c

ALL_SRC = $(UTILS_SRC) $(SOCKS5_SRC) $(AUTH_SRC) $(USERS_SRC) $(METRICS_SRC) $(ADMIN_SRC) $(DNS_SRC) $(MAIN_SRC)
ALL_OBJ = $(ALL_SRC:.c=.o)

TARGET = $(BIN_DIR)/socks5d
ADMIN_CLIENT = $(BIN_DIR)/admin-client
ADMIN_CLIENT_SRC = $(SRC_DIR)/admin_client.c

.PHONY: all clean

all: $(TARGET) $(ADMIN_CLIENT)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(ALL_OBJ)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(ALL_OBJ) $(LDFLAGS)

$(ADMIN_CLIENT): $(ADMIN_CLIENT_SRC)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(ADMIN_CLIENT_SRC)

clean:
	rm -f $(TARGET) $(ADMIN_CLIENT) $(ALL_OBJ)