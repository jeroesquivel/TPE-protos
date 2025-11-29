#include "socks5.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

#include "../auth/auth.h"
#include "../utils/stm.h"
#include "handshake.h"
#include "request.h"
#include "copy.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define MAX_POOL_SIZE 500

static size_t pool_size = 0;

static void socks5_read(struct selector_key *key);
static void socks5_write(struct selector_key *key);
static void socks5_block(struct selector_key *key);
static void socks5_close(struct selector_key *key);

static void handle_error(const unsigned state, struct selector_key *key);
static void handle_done(const unsigned state, struct selector_key *key);

static const struct fd_handler socks5_handler = {
    .handle_read = socks5_read,
    .handle_write = socks5_write,
    .handle_block = socks5_block,
    .handle_close = socks5_close,
};

static void nothing(const unsigned int s, struct selector_key *key) {
}

static const struct state_definition socks5_states[] = {
    {
        .state = HANDSHAKE_READ,
        .on_arrival = handshake_read_init,
        .on_read_ready = handshake_read,
    },
    {
        .state = HANDSHAKE_WRITE,
        .on_write_ready = handshake_write,
    },
    {
        .state = AUTH_READ,
        .on_arrival = auth_read_init,
        .on_read_ready = auth_read,
    },
    {
        .state = AUTH_WRITE,
        .on_write_ready = auth_write,
    },
    {
        .state = REQUEST_READ,
        .on_arrival = request_read_init,
        .on_read_ready = request_read,
    },
    {
        .state = REQUEST_DNS,
        .on_block_ready = request_dns,
    },
    {
        .state = REQUEST_CONNECT,
        .on_write_ready = request_connect,
    },
    {
        .state = REQUEST_WRITE,
        .on_write_ready = request_write,
    },
    {
        .state = COPY,
        .on_arrival = copy_init,
        .on_read_ready = copy_read,
        .on_write_ready = copy_write,
        .on_departure = nothing,
    },
    {
        .state = DONE,
        .on_arrival = handle_done,
    },
    {
        .state = ERROR,
        .on_arrival = handle_error,
    }
};

void socks5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    int new_client_fd = accept(key->fd, (struct sockaddr *)&client_addr, &addr_len);
    if (new_client_fd < 0) {
        return;
    }
    
    if (new_client_fd > FD_SETSIZE) {
        close(new_client_fd);
        return;
    }
    
    struct socks5 *data = calloc(1, sizeof(*data));
    if (data == NULL) {
        close(new_client_fd);
        return;
    }
    
    data->stm.initial = HANDSHAKE_READ;
    data->stm.max_state = ERROR;
    data->stm.states = socks5_states;
    data->closed = false;
    data->client_fd = new_client_fd;
    data->origin_fd = -1;
    data->client_addr = client_addr;
    
    buffer_init(&data->client_buffer, BUFFER_SIZE, data->client_buffer_data);
    buffer_init(&data->origin_buffer, BUFFER_SIZE, data->origin_buffer_data);
    
    stm_init(&data->stm);
    
    if (selector_fd_set_nio(new_client_fd) == -1) {
        free(data);
        close(new_client_fd);
        return;
    }
    
    selector_status status = selector_register(key->s, new_client_fd, &socks5_handler, OP_READ, data);
    if (status != SELECTOR_SUCCESS) {
        free(data);
        close(new_client_fd);
        return;
    }
    
    pool_size++;
}

void close_connection(struct selector_key *key) {
    struct socks5 *data = ATTACHMENT(key);
    if (data->closed) {
        return;
    }
    data->closed = true;
    
    if (data->client_fd >= 0) {
        selector_unregister_fd(key->s, data->client_fd);
        close(data->client_fd);
        data->client_fd = -1;
    }
    
    if (data->origin_fd >= 0) {
        selector_unregister_fd(key->s, data->origin_fd);
        close(data->origin_fd);
        data->origin_fd = -1;
    }
    
    if (data->origin_addrinfo != NULL && data->resolution_from_getaddrinfo) {
        freeaddrinfo(data->origin_addrinfo);
    }
    
    free(data);
    
    if (pool_size > 0) {
        pool_size--;
    }
}

selector_status register_origin_selector(struct selector_key *key, int origin_fd, struct socks5 *data) {
    return selector_register(key->s, origin_fd, &socks5_handler, OP_READ, data);
}

static void socks5_read(struct selector_key *key) {
    struct state_machine *sm = &ATTACHMENT(key)->stm;
    enum socks5_state state = stm_handler_read(sm, key);
    if (state == ERROR || state == DONE) {
        close_connection(key);
    }
}

static void socks5_write(struct selector_key *key) {
    struct state_machine *sm = &ATTACHMENT(key)->stm;
    enum socks5_state state = stm_handler_write(sm, key);
    if (state == ERROR || state == DONE) {
        close_connection(key);
    }
}

static void socks5_block(struct selector_key *key) {
    struct state_machine *sm = &ATTACHMENT(key)->stm;
    enum socks5_state state = stm_handler_block(sm, key);
    if (state == ERROR || state == DONE) {
        close_connection(key);
    }
}

static void socks5_close(struct selector_key *key) {
    struct state_machine *sm = &ATTACHMENT(key)->stm;
    stm_handler_close(sm, key);
    close_connection(key);
}

static void handle_error(const unsigned state, struct selector_key *key) {
}

static void handle_done(const unsigned state, struct selector_key *key) {
}

int socks5_pool_init(void) {
    pool_size = 0;
    return 0;
}

void socks5_pool_destroy(void) {
    pool_size = 0;
}
