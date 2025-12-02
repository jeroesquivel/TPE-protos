#include "request.h"
#include "socks5.h"
#include "../users/users.h"
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

static void build_destination_string(struct request_parser *parser, char *out, size_t out_len) {
    if (parser == NULL || out == NULL || out_len == 0) {
        return;
    }

    out[0] = '\0';

    if (parser->address_type == ADDRESS_TYPE_DOMAIN) {
        strncpy(out, (char *)parser->dst_addr, out_len - 1);
        out[out_len - 1] = '\0';
    } else if (parser->address_type == ADDRESS_TYPE_IPV4) {
        inet_ntop(AF_INET, parser->dst_addr, out, (socklen_t)out_len);
    } else if (parser->address_type == ADDRESS_TYPE_IPV6) {
        inet_ntop(AF_INET6, parser->dst_addr, out, (socklen_t)out_len);
    }
}

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

static int resolve_address(struct request_parser *parser, struct addrinfo **result) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", parser->dst_port);
    
    int ret;
    if (parser->address_type == ADDRESS_TYPE_DOMAIN) {
        ret = getaddrinfo((char*)parser->dst_addr, port_str, &hints, result);
    } else if (parser->address_type == ADDRESS_TYPE_IPV4) {
        hints.ai_family = AF_INET;
        hints.ai_flags = AI_NUMERICHOST;
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, parser->dst_addr, addr_str, sizeof(addr_str));
        ret = getaddrinfo(addr_str, port_str, &hints, result);
    } else if (parser->address_type == ADDRESS_TYPE_IPV6) {
        hints.ai_family = AF_INET6;
        hints.ai_flags = AI_NUMERICHOST;
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, parser->dst_addr, addr_str, sizeof(addr_str));
        ret = getaddrinfo(addr_str, port_str, &hints, result);
    } else {
        return EAI_FAMILY;
    }
    
    return ret;
}

static int try_connect(struct addrinfo *addr, int *out_fd) {
    int fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (fd < 0) {
        return -1;
    }
    
    if (selector_fd_set_nio(fd) == -1) {
        close(fd);
        return -1;
    }
    
    int ret = connect(fd, addr->ai_addr, addr->ai_addrlen);
    *out_fd = fd;
    return ret;
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
    
    if (!request_parser_is_done(parser)) {
        return REQUEST_READ;
    }

    if (request_parser_has_error(parser)) {
        request_build_response(parser, &data->origin_buffer, REQUEST_REPLY_FAILURE);
        selector_set_interest_key(key, OP_WRITE);
        return REQUEST_WRITE;
    }

    struct addrinfo *addrinfo_list = NULL;
    int gai_ret = resolve_address(parser, &addrinfo_list);
    
    if (gai_ret != 0 || addrinfo_list == NULL) {
        request_build_response(parser, &data->origin_buffer, REQUEST_REPLY_HOST_UNREACHABLE);
        selector_set_interest_key(key, OP_WRITE);
        return REQUEST_WRITE;
    }
    
    data->origin_addrinfo = addrinfo_list;
    data->current_addrinfo = addrinfo_list;
    data->resolution_from_getaddrinfo = true;

    int origin_fd = -1;
    int connect_ret = try_connect(data->current_addrinfo, &origin_fd);
    
    if (origin_fd < 0) {
        data->current_addrinfo = data->current_addrinfo->ai_next;

        while (data->current_addrinfo != NULL) {
            connect_ret = try_connect(data->current_addrinfo, &origin_fd);
            if (origin_fd >= 0) break;
            data->current_addrinfo = data->current_addrinfo->ai_next;
        }
        
        if (origin_fd < 0) {
            freeaddrinfo(addrinfo_list);
            data->origin_addrinfo = NULL;
            request_build_response(parser, &data->origin_buffer, REQUEST_REPLY_HOST_UNREACHABLE);
            selector_set_interest_key(key, OP_WRITE);
            return REQUEST_WRITE;
        }
    }

    if (register_origin_selector(key, origin_fd, data) != SELECTOR_SUCCESS) {
        close(origin_fd);
        freeaddrinfo(addrinfo_list);
        data->origin_addrinfo = NULL;
        request_build_response(parser, &data->origin_buffer, REQUEST_REPLY_FAILURE);
        selector_set_interest_key(key, OP_WRITE);
        return REQUEST_WRITE;
    }
    
    data->origin_fd = origin_fd;

    if (connect_ret == 0) {
        data->request.reply = REQUEST_REPLY_SUCCESS;
        char dest[256];
        build_destination_string(parser, dest, sizeof(dest));
        user_log_connection(data->auth.username, dest, parser->dst_port);
        request_build_response(parser, &data->origin_buffer, REQUEST_REPLY_SUCCESS);
        selector_set_interest_key(key, OP_WRITE);
        return REQUEST_WRITE;
    }
    
    if (errno == EINPROGRESS) {
        selector_set_interest(key->s, origin_fd, OP_WRITE);
        selector_set_interest_key(key, OP_NOOP);
        return REQUEST_CONNECT;
    }
    
    selector_unregister_fd(key->s, origin_fd);
    close(origin_fd);
    data->origin_fd = -1;
    
    data->current_addrinfo = data->current_addrinfo->ai_next;
    
    while (data->current_addrinfo != NULL) {
        connect_ret = try_connect(data->current_addrinfo, &origin_fd);
        
        if (origin_fd >= 0) {
            if (register_origin_selector(key, origin_fd, data) != SELECTOR_SUCCESS) {
                close(origin_fd);
                data->current_addrinfo = data->current_addrinfo->ai_next;
                continue;
            }
            
            data->origin_fd = origin_fd;
            
            if (connect_ret == 0) {
                data->request.reply = REQUEST_REPLY_SUCCESS;
                request_build_response(parser, &data->origin_buffer, REQUEST_REPLY_SUCCESS);
                selector_set_interest_key(key, OP_WRITE);
                return REQUEST_WRITE;
            }
            
            if (errno == EINPROGRESS) {
                selector_set_interest(key->s, origin_fd, OP_WRITE);
                selector_set_interest_key(key, OP_NOOP);
                return REQUEST_CONNECT;
            }

            selector_unregister_fd(key->s, origin_fd);
            close(origin_fd);
            data->origin_fd = -1;
        }
        
        data->current_addrinfo = data->current_addrinfo->ai_next;
    }
    
    freeaddrinfo(addrinfo_list);
    data->origin_addrinfo = NULL;
    request_build_response(parser, &data->origin_buffer, REQUEST_REPLY_HOST_UNREACHABLE);
    selector_set_interest_key(key, OP_WRITE);
    return REQUEST_WRITE;
}

unsigned request_connect(struct selector_key *key) {
    struct socks5 *data = ATTACHMENT(key);

    if (key->fd != data->origin_fd) {
        return REQUEST_CONNECT;
    }
    
    int error = 0;
    socklen_t len = sizeof(error);
    
    if (getsockopt(data->origin_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        error = errno;
    }
    
    if (error == 0) {
        data->request.reply = REQUEST_REPLY_SUCCESS;
        char dest[256];
        build_destination_string(data->request.parser, dest, sizeof(dest));
        user_log_connection(data->auth.username, dest, data->request.parser->dst_port);
        request_build_response(data->request.parser, &data->origin_buffer, REQUEST_REPLY_SUCCESS);
        selector_set_interest(key->s, data->client_fd, OP_WRITE);
        selector_set_interest(key->s, data->origin_fd, OP_READ);
        return REQUEST_WRITE;
    }

    selector_unregister_fd(key->s, data->origin_fd);
    close(data->origin_fd);
    data->origin_fd = -1;

    if (data->current_addrinfo != NULL) {
        data->current_addrinfo = data->current_addrinfo->ai_next;
    }
    
    while (data->current_addrinfo != NULL) {
        int origin_fd = -1;
        int connect_ret = try_connect(data->current_addrinfo, &origin_fd);
        
        if (origin_fd >= 0) {
            if (register_origin_selector(key, origin_fd, data) != SELECTOR_SUCCESS) {
                close(origin_fd);
                data->current_addrinfo = data->current_addrinfo->ai_next;
                continue;
            }
            
            data->origin_fd = origin_fd;
            
            if (connect_ret == 0) {
                data->request.reply = REQUEST_REPLY_SUCCESS;
                char dest[256];
                build_destination_string(data->request.parser, dest, sizeof(dest));
                user_log_connection(data->auth.username, dest, data->request.parser->dst_port);
                request_build_response(data->request.parser, &data->origin_buffer, REQUEST_REPLY_SUCCESS);
                selector_set_interest(key->s, data->client_fd, OP_WRITE);
                selector_set_interest(key->s, data->origin_fd, OP_READ);
                return REQUEST_WRITE;
            }
            
            if (errno == EINPROGRESS) {
                selector_set_interest(key->s, origin_fd, OP_WRITE);
                selector_set_interest(key->s, data->client_fd, OP_NOOP);
                return REQUEST_CONNECT;
            }
            
            selector_unregister_fd(key->s, origin_fd);
            close(origin_fd);
            data->origin_fd = -1;
        }
        
        data->current_addrinfo = data->current_addrinfo->ai_next;
    }
    
    if (data->origin_addrinfo != NULL && data->resolution_from_getaddrinfo) {
        freeaddrinfo(data->origin_addrinfo);
        data->origin_addrinfo = NULL;
    }
    
    data->request.reply = REQUEST_REPLY_CONNECTION_REFUSED;
    request_build_response(data->request.parser, &data->origin_buffer, REQUEST_REPLY_CONNECTION_REFUSED);
    selector_set_interest(key->s, data->client_fd, OP_WRITE);
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
    //inc
    return REQUEST_READ;
}
