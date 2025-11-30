#include "copy.h"
#include "socks5.h"
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <string.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

void copy_init(unsigned int state, struct selector_key *key) {
    struct socks5 *data = ATTACHMENT(key);
    
    if (selector_set_interest(key->s, data->client_fd, OP_READ) != SELECTOR_SUCCESS) {
        close_connection(key);
        return;
    }
    
    if (selector_set_interest(key->s, data->origin_fd, OP_READ) != SELECTOR_SUCCESS) {
        close_connection(key);
        return;
    }
}

unsigned copy_read(struct selector_key *key) {
    struct socks5 *data = ATTACHMENT(key);
    
    printf("DEBUG copy_read: fd=%d, client=%d, origin=%d\n", key->fd, data->client_fd, data->origin_fd);
    
    if (key->fd == data->client_fd) {
        //leer del cliente y escribir al origin_buffer
        size_t read_limit;
        
        if (!buffer_can_write(&data->origin_buffer)) {
            printf("DEBUG: origin_buffer full\n");
            return COPY;
        }
        
        uint8_t *read_buffer = buffer_write_ptr(&data->origin_buffer, &read_limit);
        ssize_t read_count = recv(key->fd, read_buffer, read_limit, 0);
        
        printf("DEBUG: recv from client returned %zd (errno=%d)\n", read_count, errno);
        
        if (read_count < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("DEBUG: EAGAIN, continue\n");
                return COPY;  
            }
            printf("DEBUG: recv error, returning ERROR\n");
            return ERROR;
        } else if (read_count == 0) {
            printf("DEBUG: Client closed connection\n");
            return DONE;
        }
        
        buffer_write_adv(&data->origin_buffer, read_count);
        
        size_t write_limit;
        uint8_t *write_buffer = buffer_read_ptr(&data->origin_buffer, &write_limit);
        printf("DEBUG: Sending %zu bytes to origin fd=%d\n", write_limit, data->origin_fd);
        ssize_t write_count = send(data->origin_fd, write_buffer, write_limit, MSG_NOSIGNAL);
        
        printf("DEBUG: send to origin returned %zd (errno=%d: %s)\n", write_count, errno, strerror(errno));
        
        if (write_count > 0) {
            buffer_read_adv(&data->origin_buffer, write_count);
        }
        
        if (buffer_can_read(&data->origin_buffer) || (write_count < 0 && errno == EWOULDBLOCK)) {
            if (selector_set_interest(key->s, data->origin_fd, OP_WRITE) != SELECTOR_SUCCESS) {
                return ERROR;
            }
        }
        
        return COPY;
        
    } else if (key->fd == data->origin_fd) {
        //leer del origin, escribir a client_buffer, enviar a cliente
        size_t read_limit;
        
        if (!buffer_can_write(&data->client_buffer)) {
            printf("DEBUG: client_buffer full\n");
            return COPY;
        }
        
        uint8_t *read_buffer = buffer_write_ptr(&data->client_buffer, &read_limit);
        ssize_t read_count = recv(key->fd, read_buffer, read_limit, 0);
        
        printf("DEBUG: recv from origin returned %zd (errno=%d)\n", read_count, errno);
        
        if (read_count < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("DEBUG: EAGAIN, continue\n");
                return COPY;  
            }
            printf("DEBUG: recv error, returning ERROR\n");
            return ERROR;
        } else if (read_count == 0) {
            printf("DEBUG: Origin closed connection\n");
            return DONE;
        }
        
        buffer_write_adv(&data->client_buffer, read_count);
        
        size_t write_limit;
        uint8_t *write_buffer = buffer_read_ptr(&data->client_buffer, &write_limit);
        ssize_t write_count = send(data->client_fd, write_buffer, write_limit, MSG_NOSIGNAL);
        
        printf("DEBUG: send to client returned %zd\n", write_count);
        
        if (write_count > 0) {
            buffer_read_adv(&data->client_buffer, write_count);
        }
        
        if (buffer_can_read(&data->client_buffer) || (write_count < 0 && errno == EWOULDBLOCK)) {
            if (selector_set_interest(key->s, data->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
                return ERROR;
            }
        }
        
        return COPY;
    }
    
    printf("DEBUG: Unknown fd, returning ERROR\n");
    return ERROR;
}

unsigned copy_write(struct selector_key *key) {
    struct socks5 *data = ATTACHMENT(key);
    
    if (key->fd == data->client_fd) {
        //escribir al cliente desde client_buffer
        size_t write_limit;
        
        if (!buffer_can_read(&data->client_buffer)) {
            return COPY;
        }
        
        uint8_t *write_buffer = buffer_read_ptr(&data->client_buffer, &write_limit);
        ssize_t write_count = send(key->fd, write_buffer, write_limit, MSG_NOSIGNAL);
        
        if (write_count <= 0) {
            return ERROR;
        }
        
        buffer_read_adv(&data->client_buffer, write_count);
        
        if (!buffer_can_read(&data->client_buffer)) {
            if (selector_set_interest(key->s, data->client_fd, OP_READ) != SELECTOR_SUCCESS) {
                return ERROR;
            }
        }
        
        return COPY;
        
    } else if (key->fd == data->origin_fd) {
        //escribir al origin desde origin_buffer
        size_t write_limit;
        
        if (!buffer_can_read(&data->origin_buffer)) {
            return COPY;
        }
        
        uint8_t *write_buffer = buffer_read_ptr(&data->origin_buffer, &write_limit);
        ssize_t write_count = send(key->fd, write_buffer, write_limit, MSG_NOSIGNAL);
        
        if (write_count <= 0) {
            return ERROR;
        }
        
        buffer_read_adv(&data->origin_buffer, write_count);
        
        if (!buffer_can_read(&data->origin_buffer)) {
            if (selector_set_interest(key->s, data->origin_fd, OP_READ) != SELECTOR_SUCCESS) {
                return ERROR;
            }
        }
        
        return COPY;
    }
    
    return ERROR;
}

