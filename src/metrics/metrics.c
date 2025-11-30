#include "metrics.h"
#include <pthread.h>
#include <string.h>

static struct metrics global_metrics;
static pthread_mutex_t metrics_mutex = PTHREAD_MUTEX_INITIALIZER;

void metrics_init(void) {
    pthread_mutex_lock(&metrics_mutex);
    memset(&global_metrics, 0, sizeof(global_metrics));
    global_metrics.server_start_time = time(NULL);
    pthread_mutex_unlock(&metrics_mutex);
}

struct metrics metrics_get(void) {
    pthread_mutex_lock(&metrics_mutex);
    struct metrics copy = global_metrics;
    pthread_mutex_unlock(&metrics_mutex);
    return copy;
}

void metrics_connection_opened(void) {
    pthread_mutex_lock(&metrics_mutex);
    global_metrics.total_connections++;
    global_metrics.current_connections++;
    pthread_mutex_unlock(&metrics_mutex);
}

void metrics_connection_closed(void) {
    pthread_mutex_lock(&metrics_mutex);
    if (global_metrics.current_connections > 0) {
        global_metrics.current_connections--;
    }
    pthread_mutex_unlock(&metrics_mutex);
}

void metrics_add_bytes(uint64_t bytes) {
    pthread_mutex_lock(&metrics_mutex);
    global_metrics.bytes_transferred += bytes;
    pthread_mutex_unlock(&metrics_mutex);
}
