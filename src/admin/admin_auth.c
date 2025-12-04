#include "admin_auth.h"
#include "../users/users.h"
#include <string.h>

void admin_auth_init(struct admin_auth_data *auth) {
    memset(auth, 0, sizeof(*auth));
}

int admin_auth_process_byte(struct admin_auth_data *auth, uint8_t byte, auth_state_t *state) {
    switch (*state) {
        case AUTH_STATE_VERSION:
            auth->version = byte;
            if (byte != 0x01) {
                return -1;
            }
            *state = AUTH_STATE_USER_LEN;
            break;
            
        case AUTH_STATE_USER_LEN:
            auth->user_len = byte;
            if (byte == 0) {
                return -1;
            }
            auth->bytes_processed = 0;
            *state = AUTH_STATE_USER;
            break;
            
        case AUTH_STATE_USER:
            if (auth->bytes_processed < auth->user_len) {
                auth->username[auth->bytes_processed++] = byte;
                if (auth->bytes_processed == auth->user_len) {
                    auth->username[auth->bytes_processed] = '\0';
                    auth->bytes_processed = 0;
                    *state = AUTH_STATE_PASS_LEN;
                }
            }
            break;
            
        case AUTH_STATE_PASS_LEN:
            auth->pass_len = byte;
            if (byte == 0) {
                return -1;
            }
            auth->bytes_processed = 0;
            *state = AUTH_STATE_PASS;
            break;
            
        case AUTH_STATE_PASS:
            if (auth->bytes_processed < auth->pass_len) {
                auth->password[auth->bytes_processed++] = byte;
                if (auth->bytes_processed == auth->pass_len) {
                    auth->password[auth->bytes_processed] = '\0';
                    auth->complete = true;
                    *state = AUTH_STATE_DONE;
                }
            }
            break;
            
        default:
            return -1;
    }
    
    return 0;
}

bool admin_auth_validate(const char *username, const char *password, char *out_username) {
    if (!user_authenticate(username, password)) {
        return false;
    }
    
    if (out_username != NULL) {
        strncpy(out_username, username, MAX_AUTH_USERNAME - 1);
        out_username[MAX_AUTH_USERNAME - 1] = '\0';
    }
    
    return true;
}
