#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stdint.h>
#include <stdbool.h>
#include "../utils/buffer.h"
#include "../utils/selector.h"

enum hello_state {
    HELLO_VERSION,
    HELLO_NMETHODS,
    HELLO_METHODS,
    HELLO_DONE,
    HELLO_ERROR,
};

struct hello_parser {
    enum hello_state state;
    uint8_t nmethods;
    uint8_t methods_read;
    uint8_t method;
};

void handshake_read_init(unsigned state, struct selector_key *key);
unsigned handshake_read(struct selector_key *key);
unsigned handshake_write(struct selector_key *key);

void hello_parser_init(struct hello_parser *p);
enum hello_state hello_process(struct hello_parser *p, buffer *b);
bool hello_is_done(const enum hello_state state);

#endif
