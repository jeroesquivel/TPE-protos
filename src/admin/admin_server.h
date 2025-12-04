#ifndef ADMIN_SERVER_H
#define ADMIN_SERVER_H

#include <stdint.h>
#include "../utils/selector.h"

int admin_server_init(fd_selector s, uint16_t port);
void admin_server_destroy(fd_selector s);

void admin_passive_accept(struct selector_key *key);

#endif
