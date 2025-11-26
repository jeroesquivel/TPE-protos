CPPFLAGS := -D_POSIX_C_SOURCE=200112L -D_DARWIN_C_SOURCE -include signal.h
CFLAGS   := -std=c11 -O2 -Wall -Wextra -pedantic
INCLUDES := -Isrc
LDFLAGS  :=

SRC := \
  src/buffer.c \
  src/netutils.c \
  src/parser_utils.c \
  src/parser.c \
  src/selector.c \
  src/stm.c \
  main.c

OBJ := $(SRC:.c=.o)
BIN := socks5d

.PHONY: all clean run

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)

run: $(BIN)
	./$(BIN) -p 1080