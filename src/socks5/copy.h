#ifndef COPY_H
#define COPY_H

#include "../utils/selector.h"

void copy_init(unsigned int state, struct selector_key *key);
unsigned copy_read(struct selector_key *key);
unsigned copy_write(struct selector_key *key);

#endif
