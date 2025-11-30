#include "handshake.h"
#include "socks5.h"
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdio.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

void hello_parser_init(struct hello_parser *p) {
    memset(p, 0, sizeof(*p));
    p->state = HELLO_VERSION;
    p->method = 0xFF;
}

enum hello_state hello_process(struct hello_parser *p, buffer *b) {
    while (buffer_can_read(b)) {
        uint8_t byte = buffer_read(b);
        
        switch (p->state) {
            case HELLO_VERSION:
                if (byte != 0x05) {
                    p->state = HELLO_ERROR;
                    return p->state;
                }
                p->state = HELLO_NMETHODS;
                break;
                
            case HELLO_NMETHODS:
                if (byte == 0) {
                    p->state = HELLO_ERROR;
                    return p->state;
                }
                p->nmethods = byte;
                p->methods_read = 0;
                p->state = HELLO_METHODS;
                break;
                
                case HELLO_METHODS:
                if (byte == 0x02) {
                    p->method = 0x02;
                }
                
                p->methods_read++;
                
                if (p->methods_read >= p->nmethods) {
                    if (p->method == 0xFF) {
                        p->method = 0xFF;
                    }
                    p->state = HELLO_DONE;
                    return p->state;
                }
                break;
                
            case HELLO_DONE:
            case HELLO_ERROR:
                return p->state;
        }
    }
    
    return p->state;
}

bool hello_is_done(const enum hello_state state) {
    return state == HELLO_DONE;
}

void handshake_read_init(unsigned state, struct selector_key *key) {
    struct socks5 *data = ATTACHMENT(key);
    data->hello.parser = malloc(sizeof(struct hello_parser));
    if (data->hello.parser != NULL) {
        hello_parser_init(data->hello.parser);
    }
}

unsigned handshake_read(struct selector_key *key) {
    struct socks5 *data = ATTACHMENT(key);
    struct hello_parser *p = data->hello.parser;
    
    if (p == NULL) {
        return ERROR;
    }
    
    size_t read_limit;
    uint8_t *read_buffer = buffer_write_ptr(&data->client_buffer, &read_limit);
    ssize_t read_count = recv(key->fd, read_buffer, read_limit, 0);
    
    if (read_count <= 0) {
        return ERROR;
    }
    
    buffer_write_adv(&data->client_buffer, read_count);
    hello_process(p, &data->client_buffer);
    
    if (hello_is_done(p->state)) {
        data->hello.selected_method = p->method;
        
        uint8_t response[2];
        response[0] = 0x05;
        response[1] = p->method;
        
        buffer_write(&data->origin_buffer, response[0]);
        buffer_write(&data->origin_buffer, response[1]);
        
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        
        free(p);
        data->hello.parser = NULL;
        
        return HANDSHAKE_WRITE;
    }
    
    return HANDSHAKE_READ;
}

unsigned handshake_write(struct selector_key *key) {
    struct socks5 *data = ATTACHMENT(key);
    
    size_t write_limit;
    uint8_t *write_buffer = buffer_read_ptr(&data->origin_buffer, &write_limit);
    ssize_t write_count = send(key->fd, write_buffer, write_limit, MSG_NOSIGNAL);
    
    if (write_count <= 0) {
        return ERROR;
    }
    
    buffer_read_adv(&data->origin_buffer, write_count);
    
    if (buffer_can_read(&data->origin_buffer)) {
        return HANDSHAKE_WRITE;
    }
    
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    
    return (data->hello.selected_method == 0x00) ? REQUEST_READ : AUTH_READ;
}
