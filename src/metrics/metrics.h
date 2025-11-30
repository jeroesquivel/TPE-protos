#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>
#include <time.h>

struct metrics {
    uint64_t total_connections;
    uint64_t current_connections;
    uint64_t bytes_transferred;
    time_t server_start_time;
};

void metrics_init(void);

struct metrics metrics_get(void);

void metrics_connection_opened(void);

void metrics_connection_closed(void);

void metrics_add_bytes(uint64_t bytes);

#endif
