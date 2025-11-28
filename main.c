#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>

#include "socks5.h"
#include "selector.h"
#include "buffer.h"
#include "netutils.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef OP_READ
#define OP_READ  0x01
#endif
#ifndef OP_WRITE
#define OP_WRITE 0x02
#endif

#define LISTEN_BACKLOG 128
#define BUF_SIZE 4096

static volatile sig_atomic_t stop_flag = 0;
static void on_stop(int sig){ (void)sig; stop_flag = 1; }

enum phase {
    PH_GREETING,
    PH_REQUEST,
    PH_CONNECTING,
    PH_RELAY,
    PH_CLOSING,
};

struct conn {
    int cfd;
    int rfd;
    enum phase ph;

    buffer crb, cwb;
    buffer rrb, rwb;

    uint8_t crmem[BUF_SIZE];
    uint8_t cwmem[BUF_SIZE];
    uint8_t rrmem[BUF_SIZE];
    uint8_t rwmem[BUF_SIZE];

    struct socks5 s5;

    uint8_t cmd;
    uint8_t atyp;
    uint8_t dstaddr[256];
    size_t  dstlen;
    uint16_t dstport;
};

static void accept_ready(struct selector_key *key);
static void client_read (struct selector_key *key);
static void client_write(struct selector_key *key);
static void client_close(struct selector_key *key);

static void remote_read (struct selector_key *key);
static void remote_write(struct selector_key *key);
static void remote_close(struct selector_key *key);

static const struct fd_handler CLIENT = {
    .handle_read  = client_read,
    .handle_write = client_write,
    .handle_close = client_close,
};

static const struct fd_handler REMOTE = {
    .handle_read  = remote_read,
    .handle_write = remote_write,
    .handle_close = remote_close,
};

static int set_nonblock(int fd){
    int fl = fcntl(fd, F_GETFL, 0);
    if(fl == -1) return -1;
    return fcntl(fd, F_SETFL, fl|O_NONBLOCK);
}

static int create_listener(uint16_t port){
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if(lfd < 0){ perror("socket"); return -1; }
    int yes = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(port);
    if(bind(lfd, (struct sockaddr *)&a, sizeof a) < 0){ perror("bind"); goto fail; }
    if(listen(lfd, LISTEN_BACKLOG) < 0){ perror("listen"); goto fail; }
    if(set_nonblock(lfd) < 0){ perror("nonblock"); goto fail; }
    return lfd;
fail:
    close(lfd); return -1;
}

static void conn_destroy(struct selector_key *key, struct conn *c){
    if(c == NULL) return;
    if(c->cfd != -1){
        selector_unregister_fd(key->s, c->cfd);
        close(c->cfd);
    }
    if(c->rfd != -1){
        selector_unregister_fd(key->s, c->rfd);
        close(c->rfd);
    }
    free(c);
}

static void accept_ready(struct selector_key *key){
    int lfd = key->fd;
    for(;;){
        struct sockaddr_storage ss;
        socklen_t slen = sizeof ss;
        int cfd = accept(lfd, (struct sockaddr*)&ss, &slen);
        if(cfd < 0){
            if(errno==EAGAIN || errno==EWOULDBLOCK) break;
            perror("accept"); break;
        }
        if(set_nonblock(cfd) < 0){ perror("nonblock(client)"); close(cfd); continue; }

        struct conn *c = calloc(1, sizeof *c);
        if(!c){ perror("calloc"); close(cfd); continue; }
        c->cfd = cfd;
        c->rfd = -1;
        c->ph  = PH_GREETING;

        buffer_init(&c->crb, BUF_SIZE, c->crmem);
        buffer_init(&c->cwb, BUF_SIZE, c->cwmem);
        buffer_init(&c->rrb, BUF_SIZE, c->rrmem);
        buffer_init(&c->rwb, BUF_SIZE, c->rwmem);

        socks5_init(&c->s5, &c->crb, &c->cwb);

        if(selector_register(key->s, cfd, &CLIENT, OP_READ, c) != SELECTOR_SUCCESS){
            fprintf(stderr, "selector_register(client) failed\n");
            close(cfd); free(c); continue;
        }
    }
}

static int send_reply(struct conn *c, uint8_t rep, const struct sockaddr_in *bnd){
    uint8_t *w; size_t wn;
    w = buffer_write_ptr(&c->cwb, &wn);
    if(wn < 10) return -1;
    w[0] = 0x05;
    w[1] = rep;
    w[2] = 0x00;
    w[3] = 0x01;
    if(bnd){
        memcpy(w+4, &bnd->sin_addr, 4);
        memcpy(w+8, &bnd->sin_port, 2);
    } else {
        memset(w+4, 0, 6);
    }
    buffer_write_adv(&c->cwb, 10);
    return 0;
}

static void flush_client_now(struct conn *c){
    uint8_t *src; size_t n;
    src = buffer_read_ptr(&c->cwb, &n);
    if(n > 0){
        ssize_t m = send(c->cfd, src, n, MSG_NOSIGNAL);
        if(m > 0) buffer_read_adv(&c->cwb, (size_t)m);
    }
}

static void parse_request(struct conn *c){
    size_t n; uint8_t *p = buffer_read_ptr(&c->crb, &n);
    if(n < 4) return;
    if(p[0] != 0x05){ c->ph = PH_CLOSING; return; }
    c->cmd  = p[1];
    c->atyp = p[3];

    size_t need = 0;
    if(c->atyp == 0x01){
        need = 4 + 4 + 2;
        if(n < need) return;
        memcpy(c->dstaddr, p+4, 4);
        memcpy(&c->dstport, p+8, 2);
        c->dstlen = 4;
        buffer_read_adv(&c->crb, need);
        return;
    } else if(c->atyp == 0x03){
        if(n < 5) return;
        uint8_t dlen = p[4];
        need = 4 + 1 + dlen + 2;
        if(n < need) return;
        memcpy(c->dstaddr, p+5, dlen);
        c->dstaddr[dlen] = 0;
        memcpy(&c->dstport, p+5+dlen, 2);
        c->dstlen = dlen;
        buffer_read_adv(&c->crb, need);
        return;
    } else if(c->atyp == 0x04){
        c->ph = PH_CLOSING;
        return;
    } else {
        c->ph = PH_CLOSING;
        return;
    }
}

static int connect_remote(struct selector_key *key, struct conn *c){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) return -1;
    if(set_nonblock(fd) < 0){ close(fd); return -1; }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port   = c->dstport;

    if(c->atyp == 0x01){
        memcpy(&dst.sin_addr, c->dstaddr, 4);
    } else {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        char portstr[8];
        unsigned short p = ntohs(c->dstport);
        snprintf(portstr, sizeof portstr, "%hu", p);
        int rc = getaddrinfo((char*)c->dstaddr, portstr, &hints, &res);
        if(rc != 0 || res == NULL){ close(fd); return -1; }
        memcpy(&dst, res->ai_addr, sizeof dst);
        freeaddrinfo(res);
    }

    int r = connect(fd, (struct sockaddr*)&dst, sizeof dst);

    if(r == 0){
        c->rfd = fd;
        if(selector_register(key->s, fd, &REMOTE, OP_READ | OP_WRITE, c) != SELECTOR_SUCCESS){
            close(fd); c->rfd = -1; return -1;
        }
        struct sockaddr_in bnd; socklen_t blen = sizeof bnd;
        memset(&bnd, 0, sizeof bnd);
        getsockname(c->rfd, (struct sockaddr*)&bnd, &blen);

        send_reply(c, 0x00, &bnd);
        selector_set_interest(key->s, c->cfd, OP_READ | OP_WRITE);
        selector_set_interest(key->s, c->rfd, OP_READ);
        c->ph = PH_RELAY;
        flush_client_now(c);
        return 0;
    }

    if(r < 0 && errno == EINPROGRESS){
        c->rfd = fd;
        if(selector_register(key->s, fd, &REMOTE, OP_READ | OP_WRITE, c) != SELECTOR_SUCCESS){
            close(fd); c->rfd = -1; return -1;
        }
        c->ph = PH_CONNECTING;
        return 0;
    }

    close(fd);
    return -1;
}

static void client_read(struct selector_key *key){
    struct conn *c = key->data;
    uint8_t *dst; size_t nbytes;
    dst = buffer_write_ptr(&c->crb, &nbytes);
    if(nbytes == 0){
        selector_set_interest_key(key, OP_WRITE);
        return;
    }
    ssize_t n = recv(c->cfd, dst, nbytes, 0);
    if(n > 0){
        buffer_write_adv(&c->crb, (size_t)n);

        if(c->ph == PH_GREETING){
            socks5_on_read(&c->s5);
            if(c->s5.state == GREETING_WRITE){
                selector_set_interest_key(key, OP_READ | OP_WRITE);
                client_write(key);
                return;
            } else if(c->s5.state == DONE){
                if(c->s5.selected == 0xFF){
                    c->ph = PH_CLOSING;
                } else {
                    c->ph = PH_REQUEST;
                }
            }
        } else if(c->ph == PH_REQUEST){
            parse_request(c);
            if(c->cmd != 0x01 && c->ph != PH_CLOSING){
                uint8_t *w; size_t wn;
                w = buffer_write_ptr(&c->cwb, &wn);
                if(wn >= 10){
                    send_reply(c, 0x07, NULL);
                    selector_set_interest_key(key, OP_READ | OP_WRITE);
                }
                c->ph = PH_CLOSING;
            } else if(c->dstlen > 0 && c->ph != PH_CLOSING){
                if(connect_remote(key, c) == 0){
                } else {
                    send_reply(c, 0x01, NULL);
                    selector_set_interest_key(key, OP_READ | OP_WRITE);
                    c->ph = PH_CLOSING;
                }
            }
        } else if(c->ph == PH_RELAY){
            uint8_t *sp; size_t sn;
            sp = buffer_read_ptr(&c->crb, &sn);
            if(sn > 0){
                size_t wn; uint8_t *wp = buffer_write_ptr(&c->rwb, &wn);
                size_t x = sn < wn ? sn : wn;
                if(x > 0){
                    memcpy(wp, sp, x);
                    buffer_read_adv(&c->crb, x);
                    buffer_write_adv(&c->rwb, x);
                    selector_set_interest(key->s, c->rfd, OP_READ | OP_WRITE);
                }
            }
        }
    } else if(n == 0){
        c->ph = PH_CLOSING;
    } else {
        if(errno!=EAGAIN && errno!=EWOULDBLOCK)
            c->ph = PH_CLOSING;
    }
}

static void client_write(struct selector_key *key){
    struct conn *c = key->data;

    if(c->ph == PH_GREETING && c->s5.state == GREETING_WRITE){
        uint8_t *src; size_t nbytes;
        src = buffer_read_ptr(&c->cwb, &nbytes);
        if(nbytes == 0){
            selector_set_interest_key(key, OP_READ);
            return;
        }
        ssize_t n = send(c->cfd, src, nbytes, MSG_NOSIGNAL);
        if(n > 0){
            buffer_read_adv(&c->cwb, (size_t)n);
            socks5_on_write(&c->s5);
            selector_set_interest_key(key, OP_READ);
        } else if(n < 0 && errno != EAGAIN && errno != EWOULDBLOCK){
            c->ph = PH_CLOSING;
        }
        return;
    }

    if(c->ph == PH_RELAY){
        uint8_t *src; size_t nbytes;
        src = buffer_read_ptr(&c->cwb, &nbytes);
        if(nbytes == 0){
            selector_set_interest_key(key, OP_READ);
            return;
        }
        ssize_t n = send(c->cfd, src, nbytes, MSG_NOSIGNAL);
        if(n > 0){
            buffer_read_adv(&c->cwb, (size_t)n);
            selector_set_interest_key(key, buffer_can_read(&c->cwb) ? (OP_READ|OP_WRITE) : OP_READ);
        }else if(n < 0){
            if(errno!=EAGAIN && errno!=EWOULDBLOCK)
                c->ph = PH_CLOSING;
        }
        return;
    }

    if(c->ph == PH_CLOSING){
        uint8_t *src; size_t nbytes;
        src = buffer_read_ptr(&c->cwb, &nbytes);
        if(nbytes > 0){
            ssize_t n = send(c->cfd, src, nbytes, MSG_NOSIGNAL);
            if(n > 0) buffer_read_adv(&c->cwb, (size_t)n);
        }
    }
}

static void client_close(struct selector_key *key){
    struct conn *c = key->data;
    conn_destroy(key, c);
}

static void remote_read(struct selector_key *key){
    struct conn *c = key->data;

    if(c->ph == PH_CONNECTING){
        int err = 0; socklen_t errlen = sizeof err;
        if(getsockopt(c->rfd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0){
            send_reply(c, 0x05, NULL);
            selector_set_interest(key->s, c->cfd, OP_READ | OP_WRITE);
            c->ph = PH_CLOSING;
            flush_client_now(c);
            return;
        }
        struct sockaddr_in bnd; socklen_t blen = sizeof bnd;
        memset(&bnd, 0, sizeof bnd);
        getsockname(c->rfd, (struct sockaddr*)&bnd, &blen);

        send_reply(c, 0x00, &bnd);
        selector_set_interest(key->s, c->cfd, OP_READ | OP_WRITE);
        selector_set_interest_key(key, OP_READ);
        c->ph = PH_RELAY;
        flush_client_now(c);
        return;
    }

    if(c->ph != PH_RELAY){ return; }

    uint8_t *dst; size_t nbytes;
    dst = buffer_write_ptr(&c->rrb, &nbytes);
    if(nbytes == 0){
        selector_set_interest_key(key, OP_WRITE);
        return;
    }
    ssize_t n = recv(c->rfd, dst, nbytes, 0);
    if(n > 0){
        buffer_write_adv(&c->rrb, (size_t)n);
        uint8_t *sp; size_t sn;
        sp = buffer_read_ptr(&c->rrb, &sn);
        if(sn > 0){
            size_t wn; uint8_t *wp = buffer_write_ptr(&c->cwb, &wn);
            size_t x = sn < wn ? sn : wn;
            if(x > 0){
                memcpy(wp, sp, x);
                buffer_read_adv(&c->rrb, x);
                buffer_write_adv(&c->cwb, x);
                selector_set_interest(key->s, c->cfd, OP_READ | OP_WRITE);
            }
        }
    } else if(n == 0){
        c->ph = PH_CLOSING;
    } else {
        if(errno!=EAGAIN && errno!=EWOULDBLOCK)
            c->ph = PH_CLOSING;
    }
}

static void remote_write(struct selector_key *key){
    struct conn *c = key->data;

    if(c->ph == PH_CONNECTING){
        int err = 0; socklen_t errlen = sizeof err;
        if(getsockopt(c->rfd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0){
            send_reply(c, 0x05, NULL);
            selector_set_interest(key->s, c->cfd, OP_READ | OP_WRITE);
            c->ph = PH_CLOSING;
            flush_client_now(c);
            return;
        }
        struct sockaddr_in bnd; socklen_t blen = sizeof bnd;
        memset(&bnd, 0, sizeof bnd);
        getsockname(c->rfd, (struct sockaddr*)&bnd, &blen);

        send_reply(c, 0x00, &bnd);
        selector_set_interest(key->s, c->cfd, OP_READ | OP_WRITE);
        selector_set_interest_key(key, OP_READ);
        c->ph = PH_RELAY;
        flush_client_now(c);
        return;
    }

    if(c->ph != PH_RELAY) return;

    uint8_t *src; size_t nbytes;
    src = buffer_read_ptr(&c->rwb, &nbytes);
    if(nbytes == 0){
        selector_set_interest_key(key, OP_READ);
        return;
    }
    ssize_t n = send(c->rfd, src, nbytes, MSG_NOSIGNAL);
    if(n > 0){
        buffer_read_adv(&c->rwb, (size_t)n);
        selector_set_interest_key(key, buffer_can_read(&c->rwb) ? (OP_READ|OP_WRITE) : OP_READ);
    } else if(n < 0){
        if(errno!=EAGAIN && errno!=EWOULDBLOCK)
            c->ph = PH_CLOSING;
    }
}

static void remote_close(struct selector_key *key){
    struct conn *c = key->data;
    if(c == NULL) return;
    if(c->rfd != -1){
        selector_unregister_fd(key->s, c->rfd);
        close(c->rfd);
        c->rfd = -1;
    }
}

int main(int argc, char **argv){
    uint16_t port = 1080;
    if(argc >= 3 && (strcmp(argv[1], "-p")==0 || strcmp(argv[1], "--port")==0))
        port = (uint16_t)atoi(argv[2]);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_stop;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    const struct selector_init conf = { .signal = SIGALRM };

    if (selector_init(&conf) != SELECTOR_SUCCESS) {
        fprintf(stderr, "selector_init failed\n");
        return 1;
    }
    fd_selector sel = selector_new(1024);
    if(!sel){ fprintf(stderr,"selector_new failed\n"); selector_close(); return 1; }

    int lfd = create_listener(port);
    if(lfd < 0){ selector_destroy(sel); selector_close(); return 1; }

    const struct fd_handler ACCEPT = { .handle_read = accept_ready };
    if(selector_register(sel, lfd, &ACCEPT, OP_READ, NULL) != SELECTOR_SUCCESS){
        fprintf(stderr,"selector_register(listen) failed\n");
        close(lfd); selector_destroy(sel); selector_close(); return 1;
    }

    printf("SOCKS5 escuchando en 0.0.0.0:%u\n", port);

    while(!stop_flag){
        selector_status st = selector_select(sel);
        if(st != SELECTOR_SUCCESS && errno != EINTR){
            fprintf(stderr, "selector_select error\n");
            break;
        }
    }

    selector_unregister_fd(sel, lfd);
    close(lfd);
    selector_destroy(sel);
    selector_close();
    return 0;
}