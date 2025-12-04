#ifndef USERS_H
#define USERS_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define MAX_USERNAME 256
#define MAX_PASSWORD 256
#define MAX_USERS 100

#define MAX_CONNECTION_LOG 1000

typedef enum {
    ROLE_USER = 0,
    ROLE_ADMIN = 1
} user_role_t;

struct user_connection {
    char username[MAX_USERNAME];
    char destination[256];
    uint16_t port;
    time_t timestamp;
};

struct user {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    bool active;
    user_role_t role;
    
    uint64_t bytes_transferred;
    uint64_t total_connections;
    time_t last_connection;
};


void users_init(void);

void users_destroy(void);

bool user_authenticate(const char *username, const char *password);

bool user_add(const char *username, const char *password, user_role_t role);

bool user_delete(const char *username);

bool user_change_password(const char *username, const char *new_password);

bool user_change_role(const char *username, user_role_t new_role);

struct user* user_find(const char *username);

int user_list(struct user **users, int max_users);

void user_update_metrics(const char *username, uint64_t bytes);

int user_count(void);

int user_log_connection(const char *username, const char *destination, uint16_t port);

int user_get_connections(struct user_connection *entries, int max_entries);

bool user_is_admin(const char *username);

#endif
