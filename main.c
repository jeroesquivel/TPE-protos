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

struct conn {
    int fd;
    buffer rb, wb;
    uint8_t rmem[BUF_SIZE];
    uint8_t wmem[BUF_SIZE];
};

static void accept_ready(struct selector_key *key);
static void client_read (struct selector_key *key);
static void client_write(struct selector_key *key);
static void client_close(struct selector_key *key);

static const struct fd_handler CLIENT = {
    .handle_read  = client_read,
    .handle_write = client_write,
    .handle_close = client_close,
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
    struct sockaddr_in a = {0};
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
        c->fd = cfd;
        buffer_init(&c->rb, BUF_SIZE, c->rmem);
        buffer_init(&c->wb, BUF_SIZE, c->wmem);

        if(selector_register(key->s, cfd, &CLIENT, OP_READ, c) != SELECTOR_SUCCESS){
            fprintf(stderr, "selector_register(client) failed\n");
            close(cfd); free(c); continue;
        }
    }
}

static void client_read(struct selector_key *key){
    struct conn *c = key->data;
    uint8_t *dst; size_t nbytes;
    dst = buffer_write_ptr(&c->wb, &nbytes);
    if(nbytes == 0){
        selector_set_interest(key->s, c->fd, OP_WRITE);
        return;
    }
    ssize_t n = recv(c->fd, dst, nbytes, 0);
    if(n > 0){
        buffer_write_adv(&c->wb, (size_t)n);
        printf("[read] %zd bytes\n", n); fflush(stdout);

        for(;;){
            uint8_t *src; size_t len;
            src = buffer_read_ptr(&c->wb, &len);
            if(len == 0) break;
            ssize_t m = send(c->fd, src, len, MSG_NOSIGNAL);
            if(m > 0){
                buffer_read_adv(&c->wb, (size_t)m);
                printf("[write] %zd bytes\n", m); fflush(stdout);
                continue;
            } else if(m < 0 && (errno==EAGAIN || errno==EWOULDBLOCK)){
                break;
            } else {
                selector_unregister_fd(key->s, c->fd);
                return;
            }
        }

        if(buffer_can_read(&c->wb)){
            selector_set_interest(key->s, c->fd, OP_READ | OP_WRITE);
        } else {
            selector_set_interest(key->s, c->fd, OP_READ);
        }
    }else if(n == 0){
        selector_unregister_fd(key->s, c->fd);
    }else{
        if(errno!=EAGAIN && errno!=EWOULDBLOCK)
            selector_unregister_fd(key->s, c->fd);
    }
}

static void client_write(struct selector_key *key){
    struct conn *c = key->data;
    uint8_t *src; size_t nbytes;
    src = buffer_read_ptr(&c->wb, &nbytes);
    if(nbytes == 0){
        selector_set_interest(key->s, c->fd, OP_READ);
        return;
    }
    ssize_t n = send(c->fd, src, nbytes, MSG_NOSIGNAL);
    if(n > 0){
        buffer_read_adv(&c->wb, (size_t)n);
        printf("[write] %zd bytes\n", n); fflush(stdout);
        selector_set_interest(key->s, c->fd, buffer_can_read(&c->wb) ? (OP_READ|OP_WRITE) : OP_READ);
    }else if(n < 0){
        if(errno!=EAGAIN && errno!=EWOULDBLOCK)
            selector_unregister_fd(key->s, c->fd);
    }
}

static void client_close(struct selector_key *key){
    struct conn *c = key->data;
    if(c){
        close(c->fd);
        free(c);
    }
}

int main(int argc, char **argv){
    uint16_t port = 1080;
    if(argc >= 3 && (strcmp(argv[1], "-p")==0 || strcmp(argv[1], "--port")==0))
        port = (uint16_t)atoi(argv[2]);

    struct sigaction sa = {0};
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

    printf("Echo NB escuchando en 0.0.0.0:%u (Ctrl+C para salir)\n", port);

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