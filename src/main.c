#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "users/users.h"
#include "utils/selector.h"
#include "socks5/socks5.h"

#define MAX_PENDING 20

static bool done = false;

static void
sigterm_handler(const int signal) {
    printf("Signal %d, cleaning up and exiting\n", signal);
    done = true;
}

int main(int argc, char **argv) {
    unsigned port = 1080;
    const char *socks_addr = "0.0.0.0";
    
    int opt;
    while ((opt = getopt(argc, argv, "p:l:")) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            case 'l':
                socks_addr = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-p port] [-l addr]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    close(STDIN_FILENO);
    
    const char *err_msg = NULL;
    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;
    int server = -1;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    
    if (inet_pton(AF_INET, socks_addr, &addr.sin_addr) <= 0) {
        err_msg = "Invalid address";
        goto finally;
    }
    
    addr.sin_port = htons(port);
    
    server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server < 0) {
        err_msg = "Unable to create socket";
        goto finally;
    }
    
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    
    if (bind(server, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        err_msg = "Unable to bind socket";
        goto finally;
    }
    
    if (listen(server, MAX_PENDING) < 0) {
        err_msg = "Unable to listen";
        goto finally;
    }
    
    if (selector_fd_set_nio(server) == -1) {
        err_msg = "Getting server socket flags";
        goto finally;
    }
    
    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec = 10,
            .tv_nsec = 0,
        },
    };
    
    if (selector_init(&conf) != 0) {
        err_msg = "Initializing selector";
        goto finally;
    }
    
    selector = selector_new(1024);
    if (selector == NULL) {
        err_msg = "Unable to create selector";
        goto finally;
    }
    
    const struct fd_handler socksv5 = {
        .handle_read = socks5_passive_accept,
    };
    
    ss = selector_register(selector, server, &socksv5, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        err_msg = "Registering fd";
        goto finally;
    }
    
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);
    signal(SIGPIPE, SIG_IGN);
    
    printf("Starting SOCKS5 server...\n");
    printf("SOCKS port: %s:%d\n", socks_addr, port);
    printf("Admin port: 127.0.0.1:8080\n");
    printf("Server ready and listening\n");
    
    socks5_pool_init();
    users_init();

    while (!done) {
        err_msg = NULL;
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "Serving";
            goto finally;
        }
    }
    
    if (err_msg == NULL) {
        err_msg = "Closing";
    }
    
    int ret = 0;
    
finally:
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "" : err_msg,
                ss == SELECTOR_IO ? strerror(errno) : selector_error(ss));
        ret = 2;
    } else if (err_msg) {
        perror(err_msg);
        ret = 1;
    }
    
    if (selector != NULL) {
        selector_destroy(selector);
    }
    
    selector_close();
    users_destroy();
    socks5_pool_destroy();
    
    if (server >= 0) {
        close(server);
    }
    
    return ret;
}
