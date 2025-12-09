#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define htobe16(x) OSSwapHostToBigInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#else
#define _DEFAULT_SOURCE
#include <endian.h>
#endif

#include "admin_commands.h"
#include "../users/users.h"
#include "../metrics/metrics.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

bool admin_command_requires_admin(uint8_t command) {
    switch (command) {
        case ADMIN_CMD_ADD_USER:
        case ADMIN_CMD_DEL_USER:
        case ADMIN_CMD_CHANGE_PASSWORD:
        case ADMIN_CMD_CHANGE_ROLE:
            return true;
        case ADMIN_CMD_GET_METRICS:
        case ADMIN_CMD_LIST_USERS:
        case ADMIN_CMD_LIST_CONNECTIONS:
            return false;
        default:
            return false;
    }
}

void admin_process_get_metrics(struct admin_response *response) {
    struct metrics m = metrics_get();

    uint8_t *ptr = response->data;

    uint64_t net64 = htobe64(m.total_connections);
    memcpy(ptr, &net64, 8);
    ptr += 8;

    net64 = htobe64(m.current_connections);
    memcpy(ptr, &net64, 8);
    ptr += 8;

    net64 = htobe64(m.bytes_transferred);
    memcpy(ptr, &net64, 8);
    ptr += 8;

    net64 = htobe64((uint64_t)m.server_start_time);
    memcpy(ptr, &net64, 8);
    ptr += 8;

    response->status = ADMIN_STATUS_OK;
    response->length = 32;
}

void admin_process_list_users(struct admin_response *response) {
    struct user *users_array[MAX_USERS];
    int count = user_list(users_array, MAX_USERS);

    uint8_t *ptr = response->data;
    uint8_t *end = response->data + sizeof(response->data);

    *ptr++ = (uint8_t)count;

    for (int i = 0; i < count; i++) {
        size_t username_len = strlen(users_array[i]->username);
        if (username_len > 255) username_len = 255;

        size_t needed = 1 + username_len + 16;
        if (ptr + needed > end) {
            response->data[0] = (uint8_t)i;
            break;
        }

        *ptr++ = (uint8_t)username_len;
        memcpy(ptr, users_array[i]->username, username_len);
        ptr += username_len;

        uint64_t bytes_net = htobe64(users_array[i]->bytes_transferred);
        memcpy(ptr, &bytes_net, 8);
        ptr += 8;

        uint64_t conn_net = htobe64(users_array[i]->total_connections);
        memcpy(ptr, &conn_net, 8);
        ptr += 8;
    }

    response->status = ADMIN_STATUS_OK;
    response->length = ptr - response->data;
}

void admin_process_add_user(struct admin_response *response, const char *data) {
    size_t username_len = strlen(data);
    if (username_len == 0 || username_len >= 256) {
        response->status = ADMIN_STATUS_INVALID_ARGS;
        response->length = 0;
        return;
    }

    const char *password = data + username_len + 1;
    size_t password_len = strlen(password);
    if (password_len == 0 || password_len >= 256) {
        response->status = ADMIN_STATUS_INVALID_ARGS;
        response->length = 0;
        return;
    }

    if (user_add(data, password, ROLE_USER)) {
        response->status = ADMIN_STATUS_OK;
    } else {
        response->status = ADMIN_STATUS_USER_EXISTS;
    }
    response->length = 0;
}

void admin_process_del_user(struct admin_response *response, const char *data) {
    size_t username_len = strlen(data);
    if (username_len == 0 || username_len >= 256) {
        response->status = ADMIN_STATUS_INVALID_ARGS;
        response->length = 0;
        return;
    }

    if (user_delete(data)) {
        response->status = ADMIN_STATUS_OK;
    } else {
        response->status = ADMIN_STATUS_USER_NOT_FOUND;
    }
    response->length = 0;
}

void admin_process_list_connections(struct admin_response *response) {
    struct user_connection entries[100];
    int count = user_get_connections(entries, 100);

    uint8_t *ptr = response->data;
    uint8_t *end = response->data + sizeof(response->data);

    if (count > 255) count = 255;
    *ptr++ = (uint8_t)count;

    for (int i = 0; i < count; i++) {
        size_t username_len = strlen(entries[i].username);
        if (username_len > 255) username_len = 255;

        size_t dest_len = strlen(entries[i].destination);
        if (dest_len > 255) dest_len = 255;

        size_t needed = 1 + username_len + 1 + dest_len + 2 + 8;
        if (ptr + needed > end) {
            response->data[0] = (uint8_t)i;
            break;
        }

        *ptr++ = (uint8_t)username_len;
        memcpy(ptr, entries[i].username, username_len);
        ptr += username_len;

        *ptr++ = (uint8_t)dest_len;
        memcpy(ptr, entries[i].destination, dest_len);
        ptr += dest_len;

        uint16_t port_net = htobe16(entries[i].port);
        memcpy(ptr, &port_net, 2);
        ptr += 2;

        uint64_t ts_net = htobe64((uint64_t)entries[i].timestamp);
        memcpy(ptr, &ts_net, 8);
        ptr += 8;
    }

    response->status = ADMIN_STATUS_OK;
    response->length = ptr - response->data;
}

void admin_process_change_password(struct admin_response *response, const char *data) {
    size_t username_len = strlen(data);
    if (username_len == 0 || username_len >= 256) {
        response->status = ADMIN_STATUS_INVALID_ARGS;
        response->length = 0;
        return;
    }

    const char *new_password = data + username_len + 1;
    size_t password_len = strlen(new_password);
    if (password_len == 0 || password_len >= 256) {
        response->status = ADMIN_STATUS_INVALID_ARGS;
        response->length = 0;
        return;
    }

    if (user_change_password(data, new_password)) {
        response->status = ADMIN_STATUS_OK;
    } else {
        response->status = ADMIN_STATUS_USER_NOT_FOUND;
    }
    response->length = 0;
}

void admin_process_change_role(struct admin_response *response, const char *data) {
    size_t username_len = strlen(data);
    if (username_len == 0 || username_len >= 256) {
        response->status = ADMIN_STATUS_INVALID_ARGS;
        response->length = 0;
        return;
    }

    const char *role_str = data + username_len + 1;
    user_role_t new_role;

    if (strcmp(role_str, "admin") == 0) {
        new_role = ROLE_ADMIN;
    } else if (strcmp(role_str, "user") == 0) {
        new_role = ROLE_USER;
    } else {
        response->status = ADMIN_STATUS_INVALID_ARGS;
        response->length = 0;
        return;
    }

    if (user_change_role(data, new_role)) {
        response->status = ADMIN_STATUS_OK;
    } else {
        response->status = ADMIN_STATUS_USER_NOT_FOUND;
    }
    response->length = 0;
}
