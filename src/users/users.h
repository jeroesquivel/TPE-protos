#ifndef USERS_H
#define USERS_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define MAX_USERNAME 256
#define MAX_PASSWORD 256
#define MAX_USERS 100

struct user {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    bool active;
    
    uint64_t bytes_transferred;
    uint64_t total_connections;
    time_t last_connection;
};


void users_init(void);

void users_destroy(void);

bool user_authenticate(const char *username, const char *password);

bool user_add(const char *username, const char *password);

bool user_delete(const char *username);

struct user* user_find(const char *username);

int user_list(struct user **users, int max_users);

void user_update_metrics(const char *username, uint64_t bytes);

int user_count(void);

#endif
