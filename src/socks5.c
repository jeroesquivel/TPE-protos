#include "socks5.h"

void socks5_init(struct socks5 *s, buffer *rb, buffer *wb) {
    s->state    = GREETING_READ;
    s->rb       = rb;
    s->wb       = wb;
    s->selected = 0xFF;
}