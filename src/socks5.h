#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "buffer.h"

enum socks5_state {
    GREETING_READ,
    GREETING_WRITE,
    DONE,
    ERROR
};

struct socks5 {
    enum socks5_state state;
    buffer *rb;
    buffer *wb;
    uint8_t ver;
    uint8_t nmethods;
    uint8_t methods[255];
    uint8_t selected;
};

void socks5_init(struct socks5 *s, buffer *rb, buffer *wb);
void socks5_on_read(struct socks5 *s);
void socks5_on_write(struct socks5 *s);