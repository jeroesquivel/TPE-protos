#include "socks5_handler.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int try_connect_next(socks5_connection *conn) {
    if (conn->resolution_current == NULL) {
        return -1; 
    }
    
    int fd = socket(conn->resolution_current->ai_family,
                    conn->resolution_current->ai_socktype,
                    conn->resolution_current->ai_protocol);
    
    if (fd < 0) {
        perror("socket");
        conn->resolution_current = conn->resolution_current->ai_next;
        return -1;
    }
    
    if (set_nonblocking(fd) < 0) {
        perror("set_nonblocking");
        close(fd);
        conn->resolution_current = conn->resolution_current->ai_next;
        return -1;
    }
    
    int result = connect(fd, conn->resolution_current->ai_addr,
                        conn->resolution_current->ai_addrlen);
    
    if (result == 0) {
        printf("[CONNECT] Immediate connection to origin\n");
        return fd;
    }
    
    if (errno == EINPROGRESS) {
        printf("[CONNECT] Connection in progress...\n");
        return fd;
    }
    
    perror("connect");
    close(fd);
    conn->resolution_current = conn->resolution_current->ai_next;
    return -1;
}

void connecting_arrival(const unsigned state, struct selector_key *key) {
    socks5_connection *conn = (socks5_connection *)key->data;
    printf("[STATE] Entering CONNECTING\n");
    
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; 
    hints.ai_socktype = SOCK_STREAM;
    
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", ntohs(conn->request_port));
    
    int ret;
    if (conn->request_atyp == 0x01) {
        hints.ai_family = AF_INET;
        hints.ai_flags = AI_NUMERICHOST;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &conn->request_addr.ipv4, ip_str, sizeof(ip_str));
        ret = getaddrinfo(ip_str, port_str, &hints, &conn->resolution_results);
        
    } else if (conn->request_atyp == 0x04) {
        hints.ai_family = AF_INET6;
        hints.ai_flags = AI_NUMERICHOST;
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &conn->request_addr.ipv6, ip_str, sizeof(ip_str));
        ret = getaddrinfo(ip_str, port_str, &hints, &conn->resolution_results);
        
    } else if (conn->request_atyp == 0x03) {
        ret = getaddrinfo(conn->request_addr.domain.fqdn, port_str, 
                         &hints, &conn->resolution_results);
    } else {
        ret = -1;
    }
    
    if (ret != 0) {
        fprintf(stderr, "[CONNECT] getaddrinfo failed: %s\n", gai_strerror(ret));
        conn->origin_fd = -1;
        selector_set_interest_key(key, OP_WRITE);
        return;
    }
    
    conn->resolution_current = conn->resolution_results;
    
    int fd = -1;
    while (conn->resolution_current != NULL && fd < 0) {
        fd = try_connect_next(conn);
    }
    
    if (fd < 0) {
        fprintf(stderr, "[CONNECT] All connection attempts failed\n");
        conn->origin_fd = -1;
        if (conn->resolution_results) {
            freeaddrinfo(conn->resolution_results);
            conn->resolution_results = NULL;
        }
        selector_set_interest_key(key, OP_WRITE);
        return;
    }
    
    conn->origin_fd = fd;
    
    selector_register(conn->selector, fd, 
                     &(struct fd_handler){
                         .handle_read = socks5_read_handler,
                         .handle_write = socks5_write_handler,
                         .handle_close = socks5_close_handler,
                     },
                     OP_WRITE,
                     conn);
}

unsigned connecting_read(struct selector_key *key) {
    return CONNECTING;
}

unsigned connecting_write(struct selector_key *key) {
    socks5_connection *conn = (socks5_connection *)key->data;
    
    int error = 0;
    socklen_t len = sizeof(error);
    
    if (getsockopt(conn->origin_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        perror("getsockopt");
        error = errno;
    }
    
    if (error != 0) {
        fprintf(stderr, "[CONNECT] Connection failed: %s\n", strerror(error));
        
        close(conn->origin_fd);
        selector_unregister_fd(conn->selector, conn->origin_fd);
        conn->origin_fd = -1;
        
        if (conn->resolution_current) {
            conn->resolution_current = conn->resolution_current->ai_next;
        }
        int fd = -1;
        while (conn->resolution_current != NULL && fd < 0) {
            fd = try_connect_next(conn);
        }
        
        if (fd < 0) {
            printf("[CONNECT] All addresses exhausted\n");
            if (conn->resolution_results) {
                freeaddrinfo(conn->resolution_results);
                conn->resolution_results = NULL;
            }
            return REQUEST_WRITE;
        }
        
        conn->origin_fd = fd;
        selector_register(conn->selector, fd,
                         &(struct fd_handler){
                             .handle_read = socks5_read_handler,
                             .handle_write = socks5_write_handler,
                             .handle_close = socks5_close_handler,
                         },
                         OP_WRITE, conn);
        return CONNECTING;
    }
    
    printf("[CONNECT] Successfully connected to origin\n");
    
    if (conn->resolution_results) {
        freeaddrinfo(conn->resolution_results);
        conn->resolution_results = NULL;
    }
    
    send_request_reply(conn, 0x00);
    selector_set_interest(conn->selector, conn->origin_fd, OP_READ);
    selector_set_interest(conn->selector, conn->client_fd, OP_READ | OP_WRITE);
    
    return COPY;
}

void connecting_departure(const unsigned state, struct selector_key *key) {
    printf("[STATE] Leaving CONNECTING\n");
}

extern void send_request_reply(socks5_connection *conn, uint8_t reply_code);