#include "users.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

static struct user users_db[MAX_USERS];
static int users_count = 0;
static pthread_mutex_t users_mutex = PTHREAD_MUTEX_INITIALIZER;

void users_init(void) {
    pthread_mutex_lock(&users_mutex);
    
    memset(users_db, 0, sizeof(users_db));
    users_count = 0;

    strcpy(users_db[0].username, "user");
    strcpy(users_db[0].password, "pass");
    users_db[0].active = true;
    users_db[0].bytes_transferred = 0;
    users_db[0].total_connections = 0;
    users_count = 1;
    
    pthread_mutex_unlock(&users_mutex);
}

void users_destroy(void) {
    pthread_mutex_lock(&users_mutex);
    memset(users_db, 0, sizeof(users_db));
    users_count = 0;
    pthread_mutex_unlock(&users_mutex);
}

bool user_authenticate(const char *username, const char *password) {
    if (username == NULL || password == NULL) {
        return false;
    }
    
    pthread_mutex_lock(&users_mutex);
    
    for (int i = 0; i < users_count; i++) {
        if (users_db[i].active && 
            strcmp(users_db[i].username, username) == 0 &&
            strcmp(users_db[i].password, password) == 0) {

            users_db[i].last_connection = time(NULL);
            users_db[i].total_connections++;
            
            pthread_mutex_unlock(&users_mutex);
            return true;
        }
    }
    
    pthread_mutex_unlock(&users_mutex);
    return false;
}

bool user_add(const char *username, const char *password) {
    if (username == NULL || password == NULL) {
        return false;
    }
    
    if (strlen(username) == 0 || strlen(username) >= MAX_USERNAME ||
        strlen(password) == 0 || strlen(password) >= MAX_PASSWORD) {
        return false;
    }
    
    pthread_mutex_lock(&users_mutex);

    for (int i = 0; i < users_count; i++) {
        if (strcmp(users_db[i].username, username) == 0) {
            pthread_mutex_unlock(&users_mutex);
            return false; 
        }
    }

    if (users_count >= MAX_USERS) {
        pthread_mutex_unlock(&users_mutex);
        return false;
    }

    strcpy(users_db[users_count].username, username);
    strcpy(users_db[users_count].password, password);
    users_db[users_count].active = true;
    users_db[users_count].bytes_transferred = 0;
    users_db[users_count].total_connections = 0;
    users_db[users_count].last_connection = 0;
    users_count++;
    
    pthread_mutex_unlock(&users_mutex);
    return true;
}

bool user_delete(const char *username) {
    if (username == NULL) {
        return false;
    }
    
    pthread_mutex_lock(&users_mutex);
    
    for (int i = 0; i < users_count; i++) {
        if (strcmp(users_db[i].username, username) == 0) {
            users_db[i].active = false;
            pthread_mutex_unlock(&users_mutex);
            return true;
        }
    }
    
    pthread_mutex_unlock(&users_mutex);
    return false;
}

struct user* user_find(const char *username) {
    if (username == NULL) {
        return NULL;
    }
    
    pthread_mutex_lock(&users_mutex);
    
    for (int i = 0; i < users_count; i++) {
        if (users_db[i].active && strcmp(users_db[i].username, username) == 0) {
            pthread_mutex_unlock(&users_mutex);
            return &users_db[i];
        }
    }
    
    pthread_mutex_unlock(&users_mutex);
    return NULL;
}

int user_list(struct user **users, int max_users) {
    pthread_mutex_lock(&users_mutex);
    
    int count = 0;
    for (int i = 0; i < users_count && count < max_users; i++) {
        if (users_db[i].active) {
            users[count++] = &users_db[i];
        }
    }
    
    pthread_mutex_unlock(&users_mutex);
    return count;
}

void user_update_metrics(const char *username, uint64_t bytes) {
    if (username == NULL) {
        return;
    }
    
    pthread_mutex_lock(&users_mutex);
    
    for (int i = 0; i < users_count; i++) {
        if (users_db[i].active && strcmp(users_db[i].username, username) == 0) {
            users_db[i].bytes_transferred += bytes;
            pthread_mutex_unlock(&users_mutex);
            return;
        }
    }
    
    pthread_mutex_unlock(&users_mutex);
}

int user_count(void) {
    pthread_mutex_lock(&users_mutex);
    
    int count = 0;
    for (int i = 0; i < users_count; i++) {
        if (users_db[i].active) {
            count++;
        }
    }
    
    pthread_mutex_unlock(&users_mutex);
    return count;
}
