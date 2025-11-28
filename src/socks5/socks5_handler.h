#ifndef SOCKS5_HANDLER_H
#define SOCKS5_HANDLER_H

#include <netinet/in.h>
#include "../utils/selector.h"  
#include "../utils/buffer.h"    
#include "../utils/stm.h"

#define BUFFER_SIZE 4096
#define MAX_USERS 100

enum socks5_state {
    HELLO_READ,
    HELLO_WRITE,
    AUTH_READ,
    AUTH_WRITE,
    REQUEST_READ,
    REQUEST_WRITE,
    CONNECTING,
    COPY,
    DONE,
    ERROR_ST
};

typedef struct {
    char username[256];
    char password[256];
    bool authenticated;
} socks5_user;

typedef struct socks5_connection {
    int client_fd;
    int origin_fd;
    
    struct state_machine stm;
    enum socks5_state current_state;
    
    buffer client_read_buffer;
    buffer client_write_buffer;
    uint8_t client_read_data[BUFFER_SIZE];
    uint8_t client_write_data[BUFFER_SIZE];
    
    buffer origin_read_buffer;
    buffer origin_write_buffer;
    uint8_t origin_read_data[BUFFER_SIZE];
    uint8_t origin_write_data[BUFFER_SIZE];
    
    uint8_t hello_version;
    uint8_t hello_nmethods;
    uint8_t hello_methods[255];
    uint8_t hello_selected_method;
    
    socks5_user user;
    
    uint8_t request_version;
    uint8_t request_cmd;
    uint8_t request_atyp;
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
        struct {
            uint8_t len;
            char fqdn[256];
        } domain;
    } request_addr;
    uint16_t request_port;
    
    struct addrinfo *resolution_results;
    struct addrinfo *resolution_current;
    
    fd_selector selector;
    
    uint64_t bytes_sent;
    uint64_t bytes_received;
    
} socks5_connection;

void socks5_connection_init(socks5_connection *conn, int client_fd, fd_selector selector);

void socks5_read_handler(struct selector_key *key);
void socks5_write_handler(struct selector_key *key);
void socks5_close_handler(struct selector_key *key);
void socks5_block_handler(struct selector_key *key);

void socks5_passive_accept(struct selector_key *key);

bool socks5_authenticate_user(const char *username, const char *password);

#endif 