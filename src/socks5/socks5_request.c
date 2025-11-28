#include "socks5_handler.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

 
unsigned request_read(struct selector_key *key) {
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
        return REQUEST_READ;
    }
    
    buffer_write_adv(&conn->client_read_buffer, n);
    
    size_t available;
    uint8_t *data = buffer_read_ptr(&conn->client_read_buffer, &available);
    if (available < 4) {
        return REQUEST_READ;
    }
    
    conn->request_version = data[0];
    conn->request_cmd = data[1];
    conn->request_atyp = data[3];
    
    if (conn->request_version != 0x05) {
        fprintf(stderr, "Invalid request version: 0x%02x\n", conn->request_version);
        return ERROR_ST;
    }
    
    if (conn->request_cmd != 0x01) {
        fprintf(stderr, "Unsupported command: 0x%02x\n", conn->request_cmd);
        return REQUEST_WRITE;
    }
    
    size_t addr_offset = 4;
    size_t total_needed = 4;
    
    if (conn->request_atyp == 0x01) {
        total_needed += 4 + 2;
        if (available < total_needed) {
            return REQUEST_READ;
        }
        memcpy(&conn->request_addr.ipv4, data + addr_offset, 4);
        memcpy(&conn->request_port, data + addr_offset + 4, 2);
        buffer_read_adv(&conn->client_read_buffer, total_needed);
        
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &conn->request_addr.ipv4, ip_str, sizeof(ip_str));
        printf("[REQUEST] CONNECT to %s:%d (IPv4)\n", ip_str, ntohs(conn->request_port));
        
    } else if (conn->request_atyp == 0x03) {
        if (available < 5) { 
            return REQUEST_READ;
        }
        uint8_t domain_len = data[addr_offset];
        total_needed += 1 + domain_len + 2;
        if (available < total_needed) {
            return REQUEST_READ;
        }
        conn->request_addr.domain.len = domain_len;
        memcpy(conn->request_addr.domain.fqdn, data + addr_offset + 1, domain_len);
        conn->request_addr.domain.fqdn[domain_len] = '\0';
        memcpy(&conn->request_port, data + addr_offset + 1 + domain_len, 2);
        buffer_read_adv(&conn->client_read_buffer, total_needed);
        
        printf("[REQUEST] CONNECT to %s:%d (FQDN)\n", 
               conn->request_addr.domain.fqdn, ntohs(conn->request_port));
        
    } else if (conn->request_atyp == 0x04) {
        total_needed += 16 + 2;
        if (available < total_needed) {
            return REQUEST_READ;
        }
        memcpy(&conn->request_addr.ipv6, data + addr_offset, 16);
        memcpy(&conn->request_port, data + addr_offset + 16, 2);
        buffer_read_adv(&conn->client_read_buffer, total_needed);
        
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &conn->request_addr.ipv6, ip_str, sizeof(ip_str));
        printf("[REQUEST] CONNECT to %s:%d (IPv6)\n", ip_str, ntohs(conn->request_port));
        
    } else {
        fprintf(stderr, "Unsupported address type: 0x%02x\n", conn->request_atyp);
        return REQUEST_WRITE;
    }
    
    return CONNECTING;
}

static void send_request_reply(socks5_connection *conn, uint8_t reply_code) {
    size_t space;
    uint8_t *ptr = buffer_write_ptr(&conn->client_write_buffer, &space);
    
    if (space < 10) {
        return; 
    }
    
    ptr[0] = 0x05;
    ptr[1] = reply_code;
    ptr[2] = 0x00;
    ptr[3] = 0x01; 
    
    memset(ptr + 4, 0, 6);
    
    if (conn->origin_fd >= 0 && reply_code == 0x00) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        if (getsockname(conn->origin_fd, (struct sockaddr *)&addr, &len) == 0) {
            memcpy(ptr + 4, &addr.sin_addr, 4);
            memcpy(ptr + 8, &addr.sin_port, 2);
        }
    }
    
    buffer_write_adv(&conn->client_write_buffer, 10);
}


unsigned request_write(struct selector_key *key) {
    socks5_connection *conn = (socks5_connection *)key->data;
    
    if (!buffer_can_read(&conn->client_write_buffer)) {
        uint8_t reply_code;
        
        if (conn->request_cmd != 0x01) {
            reply_code = 0x07;
        } else if (conn->request_atyp != 0x01 && 
                   conn->request_atyp != 0x03 && 
                   conn->request_atyp != 0x04) {
            reply_code = 0x08; 
        } else {
            reply_code = 0x01;
        }
        
        send_request_reply(conn, reply_code);
    }
    
    size_t nbytes;
    uint8_t *data = buffer_read_ptr(&conn->client_write_buffer, &nbytes);
    
    if (nbytes > 0) {
        ssize_t n = send(conn->client_fd, data, nbytes, MSG_NOSIGNAL);
        if (n > 0) {
            buffer_read_adv(&conn->client_write_buffer, n);
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return DONE;
        }
    }
    
    if (!buffer_can_read(&conn->client_write_buffer)) {
        return DONE;
    }
    
    return REQUEST_WRITE;
}

void request_read_arrival(const unsigned state, struct selector_key *key) {
    printf("[STATE] Entering REQUEST_READ\n");
    selector_set_interest_key(key, OP_READ);
}

void request_write_arrival(const unsigned state, struct selector_key *key) {
    printf("[STATE] Entering REQUEST_WRITE\n");
    selector_set_interest_key(key, OP_WRITE);
}