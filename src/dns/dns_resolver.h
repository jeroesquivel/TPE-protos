#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include <netdb.h>
#include "../utils/selector.h"

struct dns_request {
    char hostname[256];
    char port[6];
    void *data;
};

struct dns_response {
    struct addrinfo *result;
    int error;
    void *data;
};

typedef void (*dns_callback)(struct dns_response *response);

int dns_resolver_init(fd_selector selector);
void dns_resolver_destroy(void);

int dns_resolver_query(const char *hostname, const char *port, void *data);

void dns_resolver_set_callback(dns_callback callback);

#endif
