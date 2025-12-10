#include "dns_resolver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#define MAX_QUEUE_SIZE 100

static int pipe_fds[2] = {-1, -1};
static pthread_t worker_thread;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

static struct dns_request *request_queue[MAX_QUEUE_SIZE];
static int queue_head = 0;
static int queue_tail = 0;
static int queue_size = 0;
static bool shutdown_flag = false;

static dns_callback global_callback = NULL;
static fd_selector global_selector = NULL;

static void dns_handle_read(struct selector_key *key);

static const struct fd_handler dns_handler = {
    .handle_read = dns_handle_read,
    .handle_write = NULL,
    .handle_close = NULL,
    .handle_block = NULL,
};

static void* dns_worker(void *arg) {
    while (1) {
        pthread_mutex_lock(&queue_mutex);
        
        while (queue_size == 0 && !shutdown_flag) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }
        
        if (shutdown_flag && queue_size == 0) {
            pthread_mutex_unlock(&queue_mutex);
            break;
        }
        
        struct dns_request *req = request_queue[queue_head];
        queue_head = (queue_head + 1) % MAX_QUEUE_SIZE;
        queue_size--;
        
        pthread_mutex_unlock(&queue_mutex);
        
        struct dns_response *resp = malloc(sizeof(*resp));
        if (resp == NULL) {
            free(req);
            continue;
        }
        
        resp->data = req->data;
        
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        
        resp->error = getaddrinfo(req->hostname, req->port, &hints, &resp->result);
        
        ssize_t written = write(pipe_fds[1], &resp, sizeof(resp));
        if (written != sizeof(resp)) {
            if (resp->result != NULL) {
                freeaddrinfo(resp->result);
            }
            free(resp);
        }
        
        free(req);
    }
    
    return NULL;
}

static void dns_handle_read(struct selector_key *key) {
    struct dns_response *resp;
    ssize_t n = read(key->fd, &resp, sizeof(resp));
    
    if (n != sizeof(resp)) {
        return;
    }
    
    if (global_callback != NULL) {
        global_callback(resp);
    }
    
}

int dns_resolver_init(fd_selector selector) {
    if (pipe(pipe_fds) < 0) {
        return -1;
    }
    
    if (selector_fd_set_nio(pipe_fds[0]) == -1) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return -1;
    }
    
    global_selector = selector;
    
    if (selector_register(selector, pipe_fds[0], &dns_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return -1;
    }
    
    shutdown_flag = false;
    queue_head = 0;
    queue_tail = 0;
    queue_size = 0;
    
    if (pthread_create(&worker_thread, NULL, dns_worker, NULL) != 0) {
        selector_unregister_fd(selector, pipe_fds[0]);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return -1;
    }
    
    return 0;
}

void dns_resolver_destroy(void) {
    pthread_mutex_lock(&queue_mutex);
    shutdown_flag = true;
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);

    if (pipe_fds[1] >= 0) {
        close(pipe_fds[1]);
        pipe_fds[1] = -1;
    }
    
    pthread_join(worker_thread, NULL);
    
    if (pipe_fds[0] >= 0) {
        close(pipe_fds[0]);
        pipe_fds[0] = -1;
    }
    
    pthread_mutex_lock(&queue_mutex);
    for (int i = 0; i < queue_size; i++) {
        int idx = (queue_head + i) % MAX_QUEUE_SIZE;
        if (request_queue[idx] != NULL) {
            free(request_queue[idx]);
        }
    }
    queue_size = 0;
    pthread_mutex_unlock(&queue_mutex);
}

int dns_resolver_query(const char *hostname, const char *port, void *data) {
    if (hostname == NULL || port == NULL) {
        return -1;
    }
    
    struct dns_request *req = malloc(sizeof(*req));
    if (req == NULL) {
        return -1;
    }
    
    strncpy(req->hostname, hostname, sizeof(req->hostname) - 1);
    req->hostname[sizeof(req->hostname) - 1] = '\0';
    strncpy(req->port, port, sizeof(req->port) - 1);
    req->port[sizeof(req->port) - 1] = '\0';
    req->data = data;
    
    pthread_mutex_lock(&queue_mutex);
    
    if (queue_size >= MAX_QUEUE_SIZE) {
        pthread_mutex_unlock(&queue_mutex);
        free(req);
        return -1;
    }
    
    request_queue[queue_tail] = req;
    queue_tail = (queue_tail + 1) % MAX_QUEUE_SIZE;
    queue_size++;
    
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
    
    return 0;
}

void dns_resolver_set_callback(dns_callback callback) {
    global_callback = callback;
}
