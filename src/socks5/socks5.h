#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <netdb.h>

#include "../utils/buffer.h"
#include "../utils/selector.h"
#include "../utils/stm.h"

#define BUFFER_SIZE 8192
#define ATTACHMENT(key) ((struct socks5 *)((key)->data))

struct hello_parser;
struct request_parser;

struct socks5 {
    struct state_machine stm;
    
    bool closed;
    int client_fd;
    int origin_fd;
    
    buffer client_buffer;
    buffer origin_buffer;
    uint8_t client_buffer_data[BUFFER_SIZE];
    uint8_t origin_buffer_data[BUFFER_SIZE];
    
    struct sockaddr_storage client_addr;
    
    struct addrinfo *origin_addrinfo;
    struct addrinfo *current_addrinfo;
    bool resolution_from_getaddrinfo;
    
    struct {
        struct hello_parser *parser;
        uint8_t selected_method;
    } hello;
    
    struct {
        char username[256];
        char password[256];
        bool authenticated;
    } auth;
    
    struct {
        struct request_parser *parser;
        uint8_t reply;
    } request;
    
    fd_selector selector;
    struct selector_key *current_key;
};

enum socks5_state {
    HANDSHAKE_READ,
    HANDSHAKE_WRITE,
    AUTH_READ,
    AUTH_WRITE,
    REQUEST_READ,
    REQUEST_DNS,
    REQUEST_CONNECT,
    REQUEST_WRITE,
    COPY,
    DONE,
    ERROR
};

void socks5_passive_accept(struct selector_key *key);
void close_connection(struct selector_key *key);
selector_status register_origin_selector(struct selector_key *key, int origin_fd, struct socks5 *data);
selector_status register_origin_selector_from_key(fd_selector s, int origin_fd, struct socks5 *data);

int socks5_pool_init(void);
void socks5_pool_destroy(void);

#endif
