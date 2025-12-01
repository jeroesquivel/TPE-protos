#ifndef ADMIN_SERVER_H
#define ADMIN_SERVER_H

#include "../utils/selector.h"

int admin_server_init(fd_selector selector, unsigned port);
void admin_server_destroy(void);

void admin_passive_accept(struct selector_key *key);

#endif
