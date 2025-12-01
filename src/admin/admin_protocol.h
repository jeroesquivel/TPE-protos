#ifndef ADMIN_PROTOCOL_H
#define ADMIN_PROTOCOL_H

#include <stdint.h>

#define ADMIN_VERSION 0x01

enum admin_command {
    ADMIN_CMD_GET_METRICS = 0x01,
    ADMIN_CMD_LIST_USERS = 0x02,
    ADMIN_CMD_ADD_USER = 0x03,
    ADMIN_CMD_DEL_USER = 0x04,
    ADMIN_CMD_GET_CONFIG = 0x05,
};

enum admin_status {
    ADMIN_STATUS_OK = 0x00,
    ADMIN_STATUS_ERROR = 0x01,
    ADMIN_STATUS_INVALID_CMD = 0x02,
    ADMIN_STATUS_USER_EXISTS = 0x03,
    ADMIN_STATUS_USER_NOT_FOUND = 0x04,
};

struct admin_request {
    uint8_t version;
    uint8_t command;
    uint16_t length;
    uint8_t data[512];
};

struct admin_response {
    uint8_t version;
    uint8_t status;
    uint16_t length;
    uint8_t data[2048];
};

#endif
