#include "socks5_handler.h"
#include <string.h>
#include <stdio.h>

unsigned hello_read(struct selector_key *key) {
    socks5_connection *conn = (socks5_connection *)key->data;
    
    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(&conn->client_read_buffer, &nbytes);
    
    if (nbytes == 0) {
        return ERROR_ST;
    }
    
    ssize_t n = recv(conn->client_fd, ptr, nbytes, 0);
    
    if (n <= 0) {
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            return DONE;
        }
        return HELLO_READ; 
    }
    
    buffer_write_adv(&conn->client_read_buffer, n);
    
    size_t available;
    uint8_t *data = buffer_read_ptr(&conn->client_read_buffer, &available);
    
    if (available < 2) {
        return HELLO_READ;
    }
    
    conn->hello_version = data[0];
    conn->hello_nmethods = data[1];
    
    if (conn->hello_version != 0x05) {
        fprintf(stderr, "Invalid SOCKS version: 0x%02x\n", conn->hello_version);
        return ERROR_ST;
    }

    if (available < (size_t)(2 + conn->hello_nmethods)) {
        return HELLO_READ; 
    }

    memcpy(conn->hello_methods, data + 2, conn->hello_nmethods);
    
    buffer_read_adv(&conn->client_read_buffer, 2 + conn->hello_nmethods);
    

    // Por ahora, aceptamos solo NO AUTH (0x00)
    // TODO: Implementar USERNAME/PASSWORD (0x02)
    conn->hello_selected_method = 0xFF;
    
    for (uint8_t i = 0; i < conn->hello_nmethods; i++) {
        if (conn->hello_methods[i] == 0x00) {
            conn->hello_selected_method = 0x00;
            break;
        }
        // Descomentar cuando implementemos auth:
        // if (conn->hello_methods[i] == 0x02) {
        //     conn->hello_selected_method = 0x02;
        //     break;
        // }
    }
    
    printf("[HELLO] Client offers %d methods, selected: 0x%02x\n", 
           conn->hello_nmethods, conn->hello_selected_method);
    
    if (conn->hello_selected_method == 0xFF) {
        return ERROR_ST;
    }
    
    return HELLO_WRITE;
}

unsigned hello_write(struct selector_key *key) {
    socks5_connection *conn = (socks5_connection *)key->data;
    
    if (!buffer_can_read(&conn->client_write_buffer)) {
        size_t space;
        uint8_t *ptr = buffer_write_ptr(&conn->client_write_buffer, &space);
        
        if (space < 2) {
            return ERROR_ST;
        }
        
        ptr[0] = 0x05; 
        ptr[1] = conn->hello_selected_method; 
        buffer_write_adv(&conn->client_write_buffer, 2);
    }
    
    size_t nbytes;
    uint8_t *data = buffer_read_ptr(&conn->client_write_buffer, &nbytes);
    
    if (nbytes == 0) {
        if (conn->hello_selected_method == 0x00) {
            return REQUEST_READ;
        } else if (conn->hello_selected_method == 0x02) {
            return AUTH_READ;
        }
        return ERROR_ST;
    }
    
    ssize_t n = send(conn->client_fd, data, nbytes, MSG_NOSIGNAL);
    
    if (n <= 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return DONE;
        }
        return HELLO_WRITE;
    }
    
    buffer_read_adv(&conn->client_write_buffer, n);
    
    if (!buffer_can_read(&conn->client_write_buffer)) {
        if (conn->hello_selected_method == 0x00) {
            return REQUEST_READ;
        } else if (conn->hello_selected_method == 0x02) {
            return AUTH_READ;
        }
    }
    
    return HELLO_WRITE;
}

void hello_read_arrival(const unsigned state, struct selector_key *key) {
    printf("[STATE] Entering HELLO_READ\n");
}

void hello_read_departure(const unsigned state, struct selector_key *key) {
    printf("[STATE] Leaving HELLO_READ\n");
}

void hello_write_arrival(const unsigned state, struct selector_key *key) {
    printf("[STATE] Entering HELLO_WRITE\n");
    selector_set_interest_key(key, OP_WRITE);
}

void hello_write_departure(const unsigned state, struct selector_key *key) {
    printf("[STATE] Leaving HELLO_WRITE\n");
    selector_set_interest_key(key, OP_READ);
}