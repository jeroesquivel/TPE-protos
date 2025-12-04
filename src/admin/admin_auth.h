#ifndef ADMIN_AUTH_H
#define ADMIN_AUTH_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define MAX_AUTH_USERNAME 256
#define MAX_AUTH_PASSWORD 256

struct admin_auth_data {
    uint8_t version;
    uint8_t user_len;
    char username[MAX_AUTH_USERNAME];
    uint8_t pass_len;
    char password[MAX_AUTH_PASSWORD];
    size_t bytes_processed;
    bool complete;
};

typedef enum {
    AUTH_STATE_VERSION = 0,
    AUTH_STATE_USER_LEN,
    AUTH_STATE_USER,
    AUTH_STATE_PASS_LEN,
    AUTH_STATE_PASS,
    AUTH_STATE_DONE
} auth_state_t;

void admin_auth_init(struct admin_auth_data *auth);
int admin_auth_process_byte(struct admin_auth_data *auth, uint8_t byte, auth_state_t *state);
bool admin_auth_validate(const char *username, const char *password, char *out_username);

#endif
