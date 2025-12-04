#include "admin_server.h"
#include "admin_protocol.h"
#include "admin_auth.h"
#include "admin_commands.h"
#include "../users/users.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int admin_server_fd = -1;

struct admin_client {
    int fd;
    bool authenticated;
    char username[256];
    
    struct admin_auth_data auth_data;
    auth_state_t auth_state;
    uint8_t auth_response[2];
    size_t auth_response_sent;
    
    struct admin_request request;
    struct admin_response response;
    size_t bytes_read;
    size_t bytes_written;
    bool reading_command;
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

int admin_server_init(fd_selector s, uint16_t port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    
    admin_server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (admin_server_fd < 0) {
        return -1;
    }
    
    int reuse = 1;
    setsockopt(admin_server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(port);
    
    if (bind(admin_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(admin_server_fd);
        admin_server_fd = -1;
        return -1;
    }
    
    if (listen(admin_server_fd, 20) < 0) {
        close(admin_server_fd);
        admin_server_fd = -1;
        return -1;
    }
    
    if (selector_fd_set_nio(admin_server_fd) < 0) {
        close(admin_server_fd);
        admin_server_fd = -1;
        return -1;
    }
    
    if (SELECTOR_SUCCESS != selector_register(s, admin_server_fd, &admin_accept_handler, OP_READ, NULL)) {
        close(admin_server_fd);
        admin_server_fd = -1;
        return -1;
    }
    
    return 0;
}

void admin_server_destroy(fd_selector s) {
    if (admin_server_fd != -1) {
        selector_unregister_fd(s, admin_server_fd);
        close(admin_server_fd);
        admin_server_fd = -1;
    }
}

void admin_passive_accept(struct selector_key *key) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    int client_fd = accept(key->fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        return;
    }
    
    if (selector_fd_set_nio(client_fd) < 0) {
        close(client_fd);
        return;
    }
    
    struct admin_client *client = malloc(sizeof(*client));
    if (client == NULL) {
        close(client_fd);
        return;
    }
    
    memset(client, 0, sizeof(*client));
    client->fd = client_fd;
    client->authenticated = false;
    client->auth_state = AUTH_STATE_VERSION;
    admin_auth_init(&client->auth_data);
    
    if (SELECTOR_SUCCESS != selector_register(key->s, client_fd, &admin_handler, OP_READ, client)) {
        free(client);
        close(client_fd);
        return;
    }
}

static void process_auth(struct admin_client *client, uint8_t *buffer, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (admin_auth_process_byte(&client->auth_data, buffer[i], &client->auth_state) < 0) {
            client->auth_response[0] = ADMIN_VERSION;
            client->auth_response[1] = ADMIN_STATUS_AUTH_FAILED;
            client->auth_response_sent = 0;
            return;
        }
        
        if (client->auth_data.complete) {
            if (admin_auth_validate(client->auth_data.username, client->auth_data.password, client->username)) {
                client->authenticated = true;
                client->auth_response[0] = ADMIN_VERSION;
                client->auth_response[1] = ADMIN_STATUS_OK;
            } else {
                client->auth_response[0] = ADMIN_VERSION;
                client->auth_response[1] = ADMIN_STATUS_AUTH_FAILED;
            }
            client->auth_response_sent = 0;
            return;
        }
    }
}

static void process_command(struct admin_client *client) {
    if (!client->authenticated) {
        client->response.version = ADMIN_VERSION;
        client->response.status = ADMIN_STATUS_PERMISSION_DENIED;
        client->response.length = 0;
        return;
    }
    
    if (admin_command_requires_admin(client->request.command)) {
        if (!user_is_admin(client->username)) {
            client->response.version = ADMIN_VERSION;
            client->response.status = ADMIN_STATUS_PERMISSION_DENIED;
            client->response.length = 0;
            return;
        }
    }
    
    client->response.version = ADMIN_VERSION;
    
    switch (client->request.command) {
        case ADMIN_CMD_GET_METRICS:
            admin_process_get_metrics(&client->response);
            break;
        case ADMIN_CMD_LIST_USERS:
            admin_process_list_users(&client->response);
            break;
        case ADMIN_CMD_ADD_USER:
            admin_process_add_user(&client->response, (char *)client->request.data);
            break;
        case ADMIN_CMD_DEL_USER:
            admin_process_del_user(&client->response, (char *)client->request.data);
            break;
        case ADMIN_CMD_LIST_CONNECTIONS:
            admin_process_list_connections(&client->response);
            break;
        case ADMIN_CMD_CHANGE_PASSWORD:
            admin_process_change_password(&client->response, (char *)client->request.data);
            break;
        case ADMIN_CMD_CHANGE_ROLE:
            admin_process_change_role(&client->response, (char *)client->request.data);
            break;
        default:
            client->response.status = ADMIN_STATUS_INVALID_CMD;
            client->response.length = 0;
            break;
    }
}

static void admin_client_read(struct selector_key *key) {
    struct admin_client *client = (struct admin_client *)key->data;
    
    if (!client->authenticated) {
        uint8_t buffer[512];
        ssize_t n = recv(client->fd, buffer, sizeof(buffer), 0);
        
        if (n <= 0) {
            selector_unregister_fd(key->s, client->fd);
            return;
        }
        
        process_auth(client, buffer, n);
        selector_set_interest_key(key, OP_WRITE);
        return;
    }
    
    if (client->bytes_read < 4) {
        uint8_t *ptr = (uint8_t *)&client->request + client->bytes_read;
        size_t to_read = 4 - client->bytes_read;
        
        ssize_t n = recv(client->fd, ptr, to_read, 0);
        if (n <= 0) {
            selector_unregister_fd(key->s, client->fd);
            return;
        }
        
        client->bytes_read += n;
        
        if (client->bytes_read == 4) {
            client->request.length = ntohs(client->request.length);
            if (client->request.length > sizeof(client->request.data)) {
                selector_unregister_fd(key->s, client->fd);
                return;
            }
            
            if (client->request.length == 0) {
                process_command(client);
                selector_set_interest_key(key, OP_WRITE);
                return;
            }
        }
        return;
    }
    
    size_t data_read = client->bytes_read - 4;
    size_t to_read = client->request.length - data_read;
    
    if (to_read > 0) {
        ssize_t n = recv(client->fd, client->request.data + data_read, to_read, 0);
        if (n <= 0) {
            selector_unregister_fd(key->s, client->fd);
            return;
        }
        
        client->bytes_read += n;
        data_read += n;
    }
    
    if (data_read == client->request.length) {
        process_command(client);
        selector_set_interest_key(key, OP_WRITE);
    }
}

static void admin_client_write(struct selector_key *key) {
    struct admin_client *client = (struct admin_client *)key->data;
    
    if (client->auth_data.complete && client->auth_response_sent < 2) {
        size_t remaining = 2 - client->auth_response_sent;
        ssize_t n = send(client->fd, client->auth_response + client->auth_response_sent, remaining, MSG_NOSIGNAL);
        
        if (n <= 0) {
            selector_unregister_fd(key->s, client->fd);
            return;
        }
        
        client->auth_response_sent += n;
        
        if (client->auth_response_sent == 2) {
            if (client->authenticated) {
                client->bytes_read = 0;
                client->reading_command = true;
                selector_set_interest_key(key, OP_READ);
            } else {
                selector_unregister_fd(key->s, client->fd);
            }
        }
        return;
    }
    
    if (client->bytes_written < 4) {
        uint8_t header[4];
        header[0] = client->response.version;
        header[1] = client->response.status;
        uint16_t len_net = htons(client->response.length);
        memcpy(header + 2, &len_net, 2);
        
        size_t to_write = 4 - client->bytes_written;
        ssize_t n = send(client->fd, header + client->bytes_written, to_write, MSG_NOSIGNAL);
        
        if (n <= 0) {
            selector_unregister_fd(key->s, client->fd);
            return;
        }
        
        client->bytes_written += n;
        return;
    }
    
    size_t data_written = client->bytes_written - 4;
    size_t to_write = client->response.length - data_written;
    
    if (to_write > 0) {
        ssize_t n = send(client->fd, client->response.data + data_written, to_write, MSG_NOSIGNAL);
        
        if (n <= 0) {
            selector_unregister_fd(key->s, client->fd);
            return;
        }
        
        client->bytes_written += n;
        data_written += n;
    }
    
    if (data_written == client->response.length) {
        client->bytes_read = 0;
        client->bytes_written = 0;
        memset(&client->request, 0, sizeof(client->request));
        memset(&client->response, 0, sizeof(client->response));
        selector_set_interest_key(key, OP_READ);
    }
}

static void admin_client_close(struct selector_key *key) {
    struct admin_client *client = (struct admin_client *)key->data;
    if (client != NULL) {
        close(client->fd);
        free(client);
    }
}
