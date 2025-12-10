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

#include "utils/selector.h"
#include "socks5/socks5.h"
#include "users/users.h"
#include "metrics/metrics.h"
#include "admin/admin_server.h"
#include "dns/dns_resolver.h"
#include "utils/args.h"

#define MAX_PENDING 20

static bool done = false;

static void
sigterm_handler(const int signal) {
    printf("Signal %d, cleaning up and exiting\n", signal);
    done = true;
}

extern void dns_callback_handler(struct dns_response *response);

int main(int argc, char **argv) {
    struct socks5args args;
    parse_args(argc, argv, &args);
    
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    close(STDIN_FILENO);
    
    const char *err_msg = NULL;
    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;
    int server = -1;
    
    struct sockaddr_storage addr;
    socklen_t addr_len;
    memset(&addr, 0, sizeof(addr));
    
    int ret = 0;

    int is_ipv6 = (strchr(args.socks_addr, ':') != NULL);
    
    if (is_ipv6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(args.socks_port);
        
        if (inet_pton(AF_INET6, args.socks_addr, &addr6->sin6_addr) <= 0) {
            err_msg = "Invalid IPv6 address";
        } else {
            addr_len = sizeof(struct sockaddr_in6);
            server = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
            int no = 0;
            setsockopt(server, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
        }
    } else {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(args.socks_port);
        
        if (inet_pton(AF_INET, args.socks_addr, &addr4->sin_addr) <= 0) {
            err_msg = "Invalid IPv4 address";
        } else {
            addr_len = sizeof(struct sockaddr_in);
            server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        }
    }

    if (err_msg == NULL) {
        if (server < 0) {
            err_msg = "Unable to create socket";
        } else {
            setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

            if (bind(server, (struct sockaddr*)&addr, addr_len) < 0) {
                err_msg = "Unable to bind socket";
            } else if (listen(server, MAX_PENDING) < 0) {
                err_msg = "Unable to listen";
            } else if (selector_fd_set_nio(server) == -1) {
                err_msg = "Getting server socket flags";
            } else {
                const struct selector_init conf = {
                    .signal = SIGALRM,
                    .select_timeout = {
                        .tv_sec = 10,
                        .tv_nsec = 0,
                    },
                };

                if (selector_init(&conf) != 0) {
                    err_msg = "Initializing selector";
                } else {
                    selector = selector_new(1024);
                    if (selector == NULL) {
                        err_msg = "Unable to create selector";
                    } else {
                        const struct fd_handler socksv5 = {
                            .handle_read = socks5_passive_accept,
                        };

                        ss = selector_register(selector, server, &socksv5, OP_READ, NULL);
                        if (ss != SELECTOR_SUCCESS) {
                            err_msg = "Registering fd";
                        } else {
                            signal(SIGTERM, sigterm_handler);
                            signal(SIGINT, sigterm_handler);
                            signal(SIGPIPE, SIG_IGN);

                            printf("Starting SOCKS5 server...\n");
                            printf("SOCKS port: %s:%d\n", args.socks_addr, args.socks_port);
                            printf("Admin port: %s:%d\n", args.mng_addr, args.mng_port);
                            printf("Server ready and listening\n");

                            socks5_pool_init();
                            users_init(&args);
                            metrics_init();

                            dns_resolver_set_callback(dns_callback_handler);
                            if (dns_resolver_init(selector) != 0) {
                                fprintf(stderr, "Warning: Could not start DNS resolver\n");
                            }

                            if (admin_server_init(selector, args.mng_port) != 0) {
                                fprintf(stderr, "Warning: Could not start admin server\n");
                            }

                            while (!done) {
                                err_msg = NULL;
                                ss = selector_select(selector);
                                if (ss != SELECTOR_SUCCESS) {
                                    err_msg = "Serving";
                                    break;
                                }
                            }

                            if (err_msg == NULL && ss == SELECTOR_SUCCESS) {
                                err_msg = "Closing";
                            }
                        }
                    }
                }
            }
        }
    }

    if (ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "" : err_msg,
                ss == SELECTOR_IO ? strerror(errno) : selector_error(ss));
        ret = 2;
    } else if (err_msg) {
        perror(err_msg);
        ret = 1;
    }
    
    if (selector != NULL) {
        admin_server_destroy(selector);
    }

    if (selector != NULL) {
        selector_destroy(selector);
        selector = NULL;
    }

    selector_close();
    dns_resolver_destroy();
    users_destroy();
    socks5_pool_destroy();
    
    if (server >= 0) {
        close(server);
    }
    
    return ret;
}
