#include "request.h"
#include "socks5.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

void request_parser_init(struct request_parser *parser) {
    if (parser == NULL) return;
    parser->state = REQUEST_VERSION;
    parser->dst_port = 0;
    parser->dst_addr_length = 0;
    parser->bytes_read = 0;
}

enum request_state request_parser_consume(struct request_parser *parser, buffer *b) {
    while (buffer_can_read(b) && !request_parser_is_done(parser)) {
        uint8_t c = buffer_read(b);
        
        switch (parser->state) {
            case REQUEST_VERSION:
                parser->state = (c == 0x05) ? REQUEST_CMD : REQUEST_ERROR;
                break;
                
            case REQUEST_CMD:
                if (c == REQUEST_COMMAND_CONNECT) {
                    parser->command = c;
                    parser->state = REQUEST_RSV;
                } else {
                    parser->state = REQUEST_ERROR;
                }
                break;
                
            case REQUEST_RSV:
                parser->state = (c == 0x00) ? REQUEST_ATYP : REQUEST_ERROR;
                break;
                
            case REQUEST_ATYP:
                parser->address_type = c;
                parser->bytes_read = 0;
                switch (c) {
                    case ADDRESS_TYPE_IPV4:
                        parser->dst_addr_length = IPV4_LENGTH;
                        parser->state = REQUEST_DSTADDR;
                        break;
                    case ADDRESS_TYPE_IPV6:
                        parser->dst_addr_length = IPV6_LENGTH;
                        parser->state = REQUEST_DSTADDR;
                        break;
                    case ADDRESS_TYPE_DOMAIN:
                        parser->state = REQUEST_DSTADDR;
                        break;
                    default:
                        parser->state = REQUEST_ERROR;
                }
                break;
                
            case REQUEST_DSTADDR:
                if (parser->address_type == ADDRESS_TYPE_DOMAIN && parser->bytes_read == 0) {
                    parser->dst_addr_length = c;
                    parser->bytes_read++;
                } else {
                    size_t index = parser->bytes_read - (parser->address_type == ADDRESS_TYPE_DOMAIN ? 1 : 0);
                    if (index >= sizeof(parser->dst_addr)) {
                        parser->state = REQUEST_ERROR;
                        break;
                    }
                    
                    parser->dst_addr[index] = c;
                    parser->bytes_read++;
                    
                    if ((parser->address_type == ADDRESS_TYPE_DOMAIN && parser->bytes_read == parser->dst_addr_length + 1) ||
                        (parser->address_type != ADDRESS_TYPE_DOMAIN && parser->bytes_read == parser->dst_addr_length)) {
                        parser->dst_addr[parser->dst_addr_length] = '\0';
                        parser->bytes_read = 0;
                        parser->state = REQUEST_DSTPORT;
                    }
                }
                break;
                
            case REQUEST_DSTPORT:
                parser->dst_port = (parser->dst_port << 8) | c;
                if (++parser->bytes_read == 2) {
                    parser->bytes_read = 0;
                    parser->state = REQUEST_DONE;
                }
                break;
                
            default:
                break;
        }
    }
    
    return parser->state;
}

bool request_parser_is_done(const struct request_parser *parser) {
    return parser != NULL && (parser->state == REQUEST_DONE || parser->state == REQUEST_ERROR);
}

bool request_parser_has_error(const struct request_parser *parser) {
    return parser != NULL && parser->state == REQUEST_ERROR;
}

bool request_build_response(const struct request_parser *parser, buffer *buf, uint8_t reply_code) {
    uint8_t answer[] = {0x05, reply_code, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    for (size_t i = 0; i < sizeof(answer); i++) {
        if (!buffer_can_write(buf)) {
            return false;
        }
        buffer_write(buf, answer[i]);
    }
    return true;
}

void request_read_init(const unsigned state, struct selector_key *key) {
    struct socks5 *data = ATTACHMENT(key);
    data->request.parser = malloc(sizeof(struct request_parser));
    if (data->request.parser != NULL) {
        request_parser_init(data->request.parser);
    }
}

unsigned request_read(struct selector_key *key) {
    struct socks5 *data = ATTACHMENT(key);
    struct request_parser *parser = data->request.parser;
    
    if (parser == NULL) {
        return ERROR;
    }
    
    size_t read_limit;
    uint8_t *read_buffer = buffer_write_ptr(&data->client_buffer, &read_limit);
    ssize_t read_count = recv(key->fd, read_buffer, read_limit, 0);
    
    if (read_count <= 0) {
        return ERROR;
    }
    
    buffer_write_adv(&data->client_buffer, read_count);
    request_parser_consume(parser, &data->client_buffer);
    
    if (request_parser_is_done(parser)) {
        if (!request_parser_has_error(parser)) {
            if (parser->address_type == ADDRESS_TYPE_IPV4) {
                struct sockaddr_in *addr = malloc(sizeof(*addr));
                data->origin_addrinfo = calloc(1, sizeof(struct addrinfo));
                if (!addr || !data->origin_addrinfo) {
                    free(addr);
                    free(data->origin_addrinfo);
                    request_build_response(parser, &data->origin_buffer, REQUEST_REPLY_FAILURE);
                    selector_set_interest_key(key, OP_WRITE);
                    return REQUEST_WRITE;
                }
                
                memcpy(&addr->sin_addr, parser->dst_addr, IPV4_LENGTH);
                addr->sin_family = AF_INET;
                addr->sin_port = htons(parser->dst_port);
                
                data->origin_addrinfo->ai_family = AF_INET;
                data->origin_addrinfo->ai_socktype = SOCK_STREAM;
                data->origin_addrinfo->ai_addr = (struct sockaddr*)addr;
                data->origin_addrinfo->ai_addrlen = sizeof(*addr);
                data->current_addrinfo = data->origin_addrinfo;
                
                int fd = socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0) {
                    request_build_response(parser, &data->origin_buffer, REQUEST_REPLY_FAILURE);
                    selector_set_interest_key(key, OP_WRITE);
                    return REQUEST_WRITE;
                }
                
                if (selector_fd_set_nio(fd) == -1) {
                    close(fd);
                    request_build_response(parser, &data->origin_buffer, REQUEST_REPLY_FAILURE);
                    selector_set_interest_key(key, OP_WRITE);
                    return REQUEST_WRITE;
                }
                
                if (register_origin_selector(key, fd, data) != SELECTOR_SUCCESS) {
                    close(fd);
                    request_build_response(parser, &data->origin_buffer, REQUEST_REPLY_FAILURE);
                    selector_set_interest_key(key, OP_WRITE);
                    return REQUEST_WRITE;
                }
                
                int ret = connect(fd, (struct sockaddr*)addr, sizeof(*addr));
                data->origin_fd = fd;
                
                if (ret == 0) {
                    data->request.reply = REQUEST_REPLY_SUCCESS;
                    request_build_response(parser, &data->origin_buffer, REQUEST_REPLY_SUCCESS);
                    selector_set_interest_key(key, OP_WRITE);
                    return REQUEST_WRITE;
                }
                
                if (errno == EINPROGRESS) {
                    selector_set_interest_key(key, OP_WRITE);
                    return REQUEST_CONNECT;
                }
                
                close(fd);
                data->origin_fd = -1;
                request_build_response(parser, &data->origin_buffer, REQUEST_REPLY_HOST_UNREACHABLE);
                selector_set_interest_key(key, OP_WRITE);
                return REQUEST_WRITE;
            }
            
            request_build_response(parser, &data->origin_buffer, REQUEST_REPLY_ADDRESS_TYPE_NOT_SUPPORTED);
            selector_set_interest_key(key, OP_WRITE);
            return REQUEST_WRITE;
        }
        
        request_build_response(parser, &data->origin_buffer, REQUEST_REPLY_FAILURE);
        selector_set_interest_key(key, OP_WRITE);
        return REQUEST_WRITE;
    }
    
    return REQUEST_READ;
}

unsigned request_connect(struct selector_key *key) {
    struct socks5 *data = ATTACHMENT(key);
    
    printf("DEBUG request_connect: called with fd=%d, origin_fd=%d\n", key->fd, data->origin_fd);
    
    int error = 0;
    socklen_t len = sizeof(error);
    
    if (getsockopt(data->origin_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        error = errno;
    }
    
    printf("DEBUG request_connect: getsockopt returned error=%d\n", error);
    
    if (error != 0) {
        close(data->origin_fd);
        data->origin_fd = -1;
        request_build_response(data->request.parser, &data->origin_buffer, REQUEST_REPLY_CONNECTION_REFUSED);
        selector_set_interest_key(key, OP_WRITE);
        return REQUEST_WRITE;
    }
    
    data->request.reply = REQUEST_REPLY_SUCCESS;
    request_build_response(data->request.parser, &data->origin_buffer, REQUEST_REPLY_SUCCESS);
    selector_set_interest_key(key, OP_WRITE);
    return REQUEST_WRITE;
}

unsigned request_write(struct selector_key *key) {
    struct socks5 *data = ATTACHMENT(key);
    
    size_t write_limit;
    uint8_t *write_buffer = buffer_read_ptr(&data->origin_buffer, &write_limit);
    ssize_t write_count = send(key->fd, write_buffer, write_limit, MSG_NOSIGNAL);
    
    if (write_count <= 0) {
        return ERROR;
    }
    
    buffer_read_adv(&data->origin_buffer, write_count);
    
    if (buffer_can_read(&data->origin_buffer)) {
        return REQUEST_WRITE;
    }
    
    if (request_parser_has_error(data->request.parser) || data->request.reply != REQUEST_REPLY_SUCCESS) {
        return ERROR;
    }
    
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    
    free(data->request.parser);
    data->request.parser = NULL;
    
    return COPY;
}

unsigned request_dns(struct selector_key *key) {
    return REQUEST_READ;
}
