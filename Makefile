CC = gcc
CFLAGS = -std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-variable -D_POSIX_C_SOURCE=200112L -DMSG_NOSIGNAL=0 -g
LDFLAGS = -pthread

SRC_DIR = src
UTILS_DIR = $(SRC_DIR)/utils
SOCKS5_DIR = $(SRC_DIR)/socks5
AUTH_DIR = $(SRC_DIR)/auth
BUILD_DIR = build
BIN_DIR = .

UTILS_SRC = $(UTILS_DIR)/buffer.c $(UTILS_DIR)/selector.c $(UTILS_DIR)/stm.c \
            $(UTILS_DIR)/netutils.c $(UTILS_DIR)/parser.c $(UTILS_DIR)/parser_utils.c
            
SOCKS5_SRC = $(SOCKS5_DIR)/socks5.c $(SOCKS5_DIR)/handshake.c \
             $(SOCKS5_DIR)/request.c $(SOCKS5_DIR)/copy.c

AUTH_SRC = $(AUTH_DIR)/auth.c

MAIN_SRC = $(SRC_DIR)/main.c

ALL_SRC = $(UTILS_SRC) $(SOCKS5_SRC) $(AUTH_SRC) $(MAIN_SRC)

UTILS_OBJ = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(UTILS_SRC))
SOCKS5_OBJ = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOCKS5_SRC))
AUTH_OBJ = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(AUTH_SRC))
MAIN_OBJ = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(MAIN_SRC))

ALL_OBJ = $(UTILS_OBJ) $(SOCKS5_OBJ) $(AUTH_OBJ) $(MAIN_OBJ)

TARGET = $(BIN_DIR)/socks5d

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(ALL_OBJ)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(TARGET)