/**
 * stm.c - pequeño motor de maquina de estados donde los eventos son los
 *         del selector.c
 */
#include <stdlib.h>
#include "stm.h"
#include <stdio.h>

#define N(x) (sizeof(x)/sizeof((x)[0]))

void
stm_init(struct state_machine *stm) {
    // verificamos que los estados son correlativos, y que están bien asignados.
    for(unsigned i = 0 ; i <= stm->max_state; i++) {
        if(i != stm->states[i].state) {
            abort();
        }
    }

    if(stm->initial < stm->max_state) {
        stm->current = NULL;
    } else {
        abort();
    }
}

inline static void
handle_first(struct state_machine *stm, struct selector_key *key) {
    if(stm->current == NULL) {
        stm->current = stm->states + stm->initial;
        if(NULL != stm->current->on_arrival) {
            stm->current->on_arrival(stm->current->state, key);
        }
    }
}

inline static
void jump(struct state_machine *stm, unsigned next, struct selector_key *key) {
    printf("[STM] jump: current=%u, next=%u, max=%u\n", 
           stm->current ? stm->current->state : 999, next, stm->max_state);
    fflush(stdout);
    
    if(next > stm->max_state) {
        fprintf(stderr, "[STM ERROR] Invalid state: %u (max: %u)\n", next, stm->max_state);
        abort();
    }
    
    if(stm->current != stm->states + next) {
        printf("[STM] Changing state\n");
        fflush(stdout);
        
        if(stm->current != NULL && stm->current->on_departure != NULL) {
            printf("[STM] Calling on_departure for state %u\n", stm->current->state);
            fflush(stdout);
            stm->current->on_departure(stm->current->state, key);
        }
        
        printf("[STM] Setting new current state to %u\n", next);
        fflush(stdout);
        stm->current = stm->states + next;
        
        printf("[STM] New current state pointer: %p\n", (void*)stm->current);
        printf("[STM] New current state value: %u\n", stm->current->state);
        printf("[STM] on_arrival pointer: %p\n", (void*)stm->current->on_arrival);
        fflush(stdout);

        if(NULL != stm->current->on_arrival) {
            printf("[STM] Calling on_arrival for state %u\n", stm->current->state);
            fflush(stdout);
            stm->current->on_arrival(stm->current->state, key);
            printf("[STM] on_arrival returned\n");
            fflush(stdout);
        }
    }
    
    printf("[STM] jump completed\n");
    fflush(stdout);
}
unsigned
stm_handler_read(struct state_machine *stm, struct selector_key *key) {
    handle_first(stm, key);
    if(stm->current->on_read_ready == 0) {
        abort();
    }
    const unsigned int ret = stm->current->on_read_ready(key);
    jump(stm, ret, key);

    return ret;
}

unsigned
stm_handler_write(struct state_machine *stm, struct selector_key *key) {
    handle_first(stm, key);
    if(stm->current->on_write_ready == 0) {
        abort();
    }
    const unsigned int ret = stm->current->on_write_ready(key);
    jump(stm, ret, key);

    return ret;
}

unsigned
stm_handler_block(struct state_machine *stm, struct selector_key *key) {
    handle_first(stm, key);
    if(stm->current->on_block_ready == 0) {
        abort();
    }
    const unsigned int ret = stm->current->on_block_ready(key);
    jump(stm, ret, key);

    return ret;
}

void
stm_handler_close(struct state_machine *stm, struct selector_key *key) {
    if(stm->current != NULL && stm->current->on_departure != NULL) {
        stm->current->on_departure(stm->current->state, key);
    }
}

unsigned
stm_state(struct state_machine *stm) {
    unsigned ret = stm->initial;
    if(stm->current != NULL) {
        ret= stm->current->state;
    }
    return ret;
}
