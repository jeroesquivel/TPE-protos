CC = gcc
CFLAGS = -std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-variable -D_POSIX_C_SOURCE=200112L -DMSG_NOSIGNAL=0 -g
LDFLAGS = -pthread

SRC_DIR = src
UTILS_DIR = $(SRC_DIR)/utils
SOCKS5_DIR = $(SRC_DIR)/socks5
AUTH_DIR = $(SRC_DIR)/auth
USERS_DIR = $(SRC_DIR)/users
METRICS_DIR = $(SRC_DIR)/metrics
ADMIN_DIR = $(SRC_DIR)/admin
ADMIN_CLIENT = $(BIN_DIR)/admin-client
DNS_DIR = $(SRC_DIR)/dns
BUILD_DIR = build
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

ADMIN_CLIENT_SRC = $(SRC_DIR)/admin_client.c

MAIN_SRC = $(SRC_DIR)/main.c

ALL_SRC = $(UTILS_SRC) $(SOCKS5_SRC) $(AUTH_SRC) $(USERS_SRC) $(METRICS_SRC) $(ADMIN_SRC) $(DNS_SRC) $(MAIN_SRC)

ALL_OBJ = $(ALL_SRC:.c=.o)

TARGET = $(BIN_DIR)/socks5d

.PHONY: all clean

all: $(TARGET) $(ADMIN_CLIENT)

$(ADMIN_CLIENT): $(ADMIN_CLIENT_SRC)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(ADMIN_CLIENT_SRC)

$(TARGET): $(ALL_SRC)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(ALL_SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET) $(ADMIN_CLIENT)