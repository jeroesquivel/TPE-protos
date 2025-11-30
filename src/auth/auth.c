#include "auth.h"
#include "../socks5/socks5.h"
#include "../users/users.h"
#include <string.h>
#include <sys/socket.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

void auth_read_init(unsigned state, struct selector_key *key) {
    struct socks5 *data = ATTACHMENT(key);
    buffer_reset(&data->client_buffer);
}

unsigned auth_read(struct selector_key *key) {
    struct socks5 *data = ATTACHMENT(key);
    
    size_t read_limit;
    uint8_t *read_buffer = buffer_write_ptr(&data->client_buffer, &read_limit);
    ssize_t read_count = recv(key->fd, read_buffer, read_limit, 0);
    
    if (read_count <= 0) {
        return ERROR;
    }
    
    buffer_write_adv(&data->client_buffer, read_count);
    
    size_t nbytes;
    uint8_t *buf = buffer_read_ptr(&data->client_buffer, &nbytes);
    
    if (nbytes < 2) {
        return AUTH_READ;
    }

    if (buf[0] != 0x01) {
        return ERROR;
    }
    
    uint8_t ulen = buf[1];
    if (nbytes < 2 + ulen + 1) {
        return AUTH_READ;
    }
    
    uint8_t plen = buf[2 + ulen];
    if (nbytes < 2 + ulen + 1 + plen) {
        return AUTH_READ;
    }

    memcpy(data->auth.username, buf + 2, ulen);
    data->auth.username[ulen] = '\0';
    memcpy(data->auth.password, buf + 2 + ulen + 1, plen);
    data->auth.password[plen] = '\0';
    
    data->auth.authenticated = user_authenticate(data->auth.username, data->auth.password);
    
    buffer_write(&data->origin_buffer, 0x01);  
    
    if (data->auth.authenticated) {
        buffer_write(&data->origin_buffer, 0x00); 
    } else {
        buffer_write(&data->origin_buffer, 0x01);  
    }
    
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    
    return AUTH_WRITE;
}

unsigned auth_write(struct selector_key *key) {
    struct socks5 *data = ATTACHMENT(key);
    
    size_t write_limit;
    uint8_t *write_buffer = buffer_read_ptr(&data->origin_buffer, &write_limit);
    ssize_t write_count = send(key->fd, write_buffer, write_limit, MSG_NOSIGNAL);
    
    if (write_count <= 0) {
        return ERROR;
    }
    
    buffer_read_adv(&data->origin_buffer, write_count);
    
    if (buffer_can_read(&data->origin_buffer)) {
        return AUTH_WRITE;
    }
    
    if (!data->auth.authenticated) {
        return ERROR;
    }
    
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    
    buffer_reset(&data->client_buffer);
    
    return REQUEST_READ;
}
