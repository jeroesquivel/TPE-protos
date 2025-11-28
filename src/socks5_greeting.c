#include "socks5.h"
#include <string.h>

static int has_no_auth(const struct socks5 *s) {
    for (uint8_t i = 0; i < s->nmethods; i++) {
        if (s->methods[i] == 0x00) return 1;
    }
    return 0;
}

void socks5_on_read(struct socks5 *s) {
    size_t n;
    uint8_t *p = buffer_read_ptr(s->rb, &n);
    if(n < 2) return;

    s->ver      = p[0];
    s->nmethods = p[1];
    if(s->ver != 0x05) { s->state = ERROR; return; }
    if(n < (size_t)(2 + s->nmethods)) return;

    if(s->nmethods > 0) {
        memcpy(s->methods, p + 2, s->nmethods);
    }
    s->selected = has_no_auth(s) ? 0x00 : 0xFF;

    buffer_read_adv(s->rb, 2 + s->nmethods);

    uint8_t *w; size_t wn;
    w = buffer_write_ptr(s->wb, &wn);
    if(wn >= 2) {
        w[0] = 0x05;
        w[1] = s->selected;
        buffer_write_adv(s->wb, 2);
        printf("[greet] reply ready: 0x%02x\n", s->selected); fflush(stdout);
        s->state = GREETING_WRITE;
    }
}

void socks5_on_write(struct socks5 *s) {
    s->state = DONE;
}