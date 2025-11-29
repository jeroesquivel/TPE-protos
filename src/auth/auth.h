#ifndef AUTH_H
#define AUTH_H

#include "../utils/selector.h"

void auth_read_init(unsigned state, struct selector_key *key);
unsigned auth_read(struct selector_key *key);
unsigned auth_write(struct selector_key *key);

#endif
