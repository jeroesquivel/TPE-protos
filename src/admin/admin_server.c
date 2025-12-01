#include "admin_server.h"
#include "admin_protocol.h"
#include "../metrics/metrics.h"
#include "../users/users.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int admin_server_fd = -1;

struct admin_client {
    int fd;
    struct admin_request request;
    struct admin_response response;
    size_t bytes_read;
    size_t bytes_written;
    bool reading;
};

static void admin_client_read(struct selector_key *key);
static void admin_client_write(struct selector_key *key);
static void admin_client_close(struct selector_key *key);

static const struct fd_handler admin_handler = {
    .handle_read = admin_client_read,
    .handle_write = admin_client_write,
    .handle_close = admin_client_close,
    .handle_block = NULL,
};

static const struct fd_handler admin_accept_handler = {
    .handle_read = admin_passive_accept,
    .handle_write = NULL,
    .handle_close = NULL,
    .handle_block = NULL,
};

static void process_get_metrics(struct admin_client *client) {
    struct metrics m = metrics_get();
    
    uint8_t *ptr = client->response.data;
    
    uint64_t total = m.total_connections;
    uint64_t current = m.current_connections;
    uint64_t bytes = m.bytes_transferred;
    uint64_t start = (uint64_t)m.server_start_time;
    
    total = htobe64(total);
    current = htobe64(current);
    bytes = htobe64(bytes);
    start = htobe64(start);
    
    memcpy(ptr, &total, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    memcpy(ptr, &current, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    memcpy(ptr, &bytes, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    memcpy(ptr, &start, sizeof(uint64_t));
    
    client->response.status = ADMIN_STATUS_OK;
    client->response.length = sizeof(uint64_t) * 4;
}

static void process_list_users(struct admin_client *client) {
    struct user *users_array[MAX_USERS];
    int count = user_list(users_array, MAX_USERS);
    
    uint8_t *ptr = client->response.data;
    *ptr++ = (uint8_t)count;
    
    for (int i = 0; i < count; i++) {
        size_t username_len = strlen(users_array[i]->username);
        *ptr++ = (uint8_t)username_len;
        memcpy(ptr, users_array[i]->username, username_len);
        ptr += username_len;
        
        uint64_t bytes = htobe64(users_array[i]->bytes_transferred);
        memcpy(ptr, &bytes, sizeof(uint64_t));
        ptr += sizeof(uint64_t);
        
        uint64_t conns = htobe64(users_array[i]->total_connections);
        memcpy(ptr, &conns, sizeof(uint64_t));
        ptr += sizeof(uint64_t);
    }
    
    client->response.status = ADMIN_STATUS_OK;
    client->response.length = ptr - client->response.data;
}

static void process_add_user(struct admin_client *client) {
    char username[256] = {0};
    char password[256] = {0};
    
    uint8_t *ptr = client->request.data;
    size_t username_len = strlen((char*)ptr);
    if (username_len >= sizeof(username)) {
        client->response.status = ADMIN_STATUS_ERROR;
        client->response.length = 0;
        return;
    }
    
    strcpy(username, (char*)ptr);
    ptr += username_len + 1;
    
    size_t password_len = strlen((char*)ptr);
    if (password_len >= sizeof(password)) {
        client->response.status = ADMIN_STATUS_ERROR;
        client->response.length = 0;
        return;
    }
    
    strcpy(password, (char*)ptr);
    
    if (user_add(username, password)) {
        client->response.status = ADMIN_STATUS_OK;
    } else {
        client->response.status = ADMIN_STATUS_USER_EXISTS;
    }
    client->response.length = 0;
}

static void process_del_user(struct admin_client *client) {
    char username[256] = {0};
    
    size_t username_len = strlen((char*)client->request.data);
    if (username_len >= sizeof(username)) {
        client->response.status = ADMIN_STATUS_ERROR;
        client->response.length = 0;
        return;
    }
    
    strcpy(username, (char*)client->request.data);
    
    if (user_delete(username)) {
        client->response.status = ADMIN_STATUS_OK;
    } else {
        client->response.status = ADMIN_STATUS_USER_NOT_FOUND;
    }
    client->response.length = 0;
}

static void process_request(struct admin_client *client) {
    client->response.version = ADMIN_VERSION;
    
    switch (client->request.command) {
        case ADMIN_CMD_GET_METRICS:
            process_get_metrics(client);
            break;
        case ADMIN_CMD_LIST_USERS:
            process_list_users(client);
            break;
        case ADMIN_CMD_ADD_USER:
            process_add_user(client);
            break;
        case ADMIN_CMD_DEL_USER:
            process_del_user(client);
            break;
        default:
            client->response.status = ADMIN_STATUS_INVALID_CMD;
            client->response.length = 0;
    }
}

void admin_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    int client_fd = accept(key->fd, (struct sockaddr *)&client_addr, &addr_len);
    if (client_fd < 0) {
        return;
    }
    
    if (selector_fd_set_nio(client_fd) == -1) {
        close(client_fd);
        return;
    }
    
    struct admin_client *client = calloc(1, sizeof(*client));
    if (client == NULL) {
        close(client_fd);
        return;
    }
    
    client->fd = client_fd;
    client->reading = true;
    client->bytes_read = 0;
    client->bytes_written = 0;
    
    if (selector_register(key->s, client_fd, &admin_handler, OP_READ, client) != SELECTOR_SUCCESS) {
        free(client);
        close(client_fd);
        return;
    }
}

static void admin_client_read(struct selector_key *key) {
    struct admin_client *client = (struct admin_client *)key->data;
    
    size_t to_read = 4 - client->bytes_read;
    if (to_read > 0) {
        uint8_t *buf = (uint8_t *)&client->request + client->bytes_read;
        ssize_t n = recv(client->fd, buf, to_read, 0);
        
        if (n <= 0) {
            selector_unregister_fd(key->s, client->fd);
            close(client->fd);
            free(client);
            return;
        }
        
        client->bytes_read += n;
        
        if (client->bytes_read == 4) {
            client->request.length = ntohs(client->request.length);
        }
    }
    
    if (client->bytes_read >= 4 && client->bytes_read < 4 + client->request.length) {
        size_t data_read = client->bytes_read - 4;
        size_t to_read = client->request.length - data_read;
        
        ssize_t n = recv(client->fd, client->request.data + data_read, to_read, 0);
        
        if (n <= 0) {
            selector_unregister_fd(key->s, client->fd);
            close(client->fd);
            free(client);
            return;
        }
        
        client->bytes_read += n;
    }
    
    if (client->bytes_read >= 4 + client->request.length) {
        process_request(client);
        
        client->reading = false;
        client->bytes_written = 0;
        
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            selector_unregister_fd(key->s, client->fd);
            close(client->fd);
            free(client);
        }
    }
}

static void admin_client_write(struct selector_key *key) {
    struct admin_client *client = (struct admin_client *)key->data;
    
    uint8_t header[4];
    header[0] = client->response.version;
    header[1] = client->response.status;
    uint16_t len_net = htons(client->response.length);
    memcpy(header + 2, &len_net, 2);
    
    if (client->bytes_written < 4) {
        ssize_t n = send(client->fd, header + client->bytes_written, 4 - client->bytes_written, MSG_NOSIGNAL);
        
        if (n <= 0) {
            selector_unregister_fd(key->s, client->fd);
            close(client->fd);
            free(client);
            return;
        }
        
        client->bytes_written += n;
    }
    
    if (client->bytes_written >= 4 && client->bytes_written < 4 + client->response.length) {
        size_t data_written = client->bytes_written - 4;
        size_t to_write = client->response.length - data_written;
        
        ssize_t n = send(client->fd, client->response.data + data_written, to_write, MSG_NOSIGNAL);
        
        if (n <= 0) {
            selector_unregister_fd(key->s, client->fd);
            close(client->fd);
            free(client);
            return;
        }
        
        client->bytes_written += n;
    }
    
    if (client->bytes_written >= 4 + client->response.length) {
        selector_unregister_fd(key->s, client->fd);
        close(client->fd);
        free(client);
    }
}

static void admin_client_close(struct selector_key *key) {
    struct admin_client *client = (struct admin_client *)key->data;
    if (client != NULL) {
        close(client->fd);
    }
}

int admin_server_init(fd_selector selector, unsigned port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(port);
    
    admin_server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (admin_server_fd < 0) {
        return -1;
    }
    
    setsockopt(admin_server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    
    if (bind(admin_server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(admin_server_fd);
        admin_server_fd = -1;
        return -1;
    }
    
    if (listen(admin_server_fd, 5) < 0) {
        close(admin_server_fd);
        admin_server_fd = -1;
        return -1;
    }
    
    if (selector_fd_set_nio(admin_server_fd) == -1) {
        close(admin_server_fd);
        admin_server_fd = -1;
        return -1;
    }
    
    if (selector_register(selector, admin_server_fd, &admin_accept_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        close(admin_server_fd);
        admin_server_fd = -1;
        return -1;
    }
    
    return 0;
}

void admin_server_destroy(void) {
    if (admin_server_fd >= 0) {
        close(admin_server_fd);
        admin_server_fd = -1;
    }
}
