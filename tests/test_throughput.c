#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>
#include <semaphore.h>

#define PROXY_HOST "127.0.0.1"
#define PROXY_PORT 1080
#define MAX_CONCURRENT_THREADS 50
#define RAMP_UP_DELAY_MS 10

typedef struct {
    const char *username;
    const char *password;
    int success;
    int thread_id;
    sem_t *semaphore;
} thread_data_t;

static int successful_connections = 0;
static int failed_connections = 0;
static pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;

double get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec) * 1000.0 + (tv.tv_usec) / 1000.0;
}

int socks5_connect(const char *username, const char *password, const char *target_host, int target_port) {
    int fd;
    struct sockaddr_in addr;
    unsigned char buffer[512];
    ssize_t n;
    
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PROXY_PORT);
    inet_pton(AF_INET, PROXY_HOST, &addr.sin_addr);
    
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    
    buffer[0] = 0x05;
    buffer[1] = 0x02;
    buffer[2] = 0x00;
    buffer[3] = 0x02;
    
    if (write(fd, buffer, 4) != 4) {
        close(fd);
        return -1;
    }
    
    n = read(fd, buffer, 2);
    if (n != 2 || buffer[0] != 0x05) {
        close(fd);
        return -1;
    }
    
    if (buffer[1] == 0x02) {
        int ulen = strlen(username);
        int plen = strlen(password);
        
        buffer[0] = 0x01;
        buffer[1] = (unsigned char)ulen;
        memcpy(buffer + 2, username, ulen);
        buffer[2 + ulen] = (unsigned char)plen;
        memcpy(buffer + 3 + ulen, password, plen);
        
        if (write(fd, buffer, 3 + ulen + plen) != (3 + ulen + plen)) {
            close(fd);
            return -1;
        }
        
        n = read(fd, buffer, 2);
        if (n != 2 || buffer[1] != 0x00) {
            close(fd);
            return -1;
        }
    }
    
    buffer[0] = 0x05;
    buffer[1] = 0x01;
    buffer[2] = 0x00;
    buffer[3] = 0x03;
    
    int target_len = strlen(target_host);
    buffer[4] = (unsigned char)target_len;
    memcpy(buffer + 5, target_host, target_len);
    buffer[5 + target_len] = (target_port >> 8) & 0xFF;
    buffer[6 + target_len] = target_port & 0xFF;
    
    if (write(fd, buffer, 7 + target_len) != (7 + target_len)) {
        close(fd);
        return -1;
    }
    
    n = read(fd, buffer, 10);
    if (n < 10 || buffer[0] != 0x05 || buffer[1] != 0x00) {
        close(fd);
        return -1;
    }
    
    char http_request[256];
    snprintf(http_request, sizeof(http_request), 
             "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", target_host);
    write(fd, http_request, strlen(http_request));
    
    n = read(fd, buffer, sizeof(buffer));
    
    close(fd);
    return (n > 0) ? 0 : -1;
}

void* connection_thread(void *arg) {
    thread_data_t *data = (thread_data_t*)arg;
    
    int result = socks5_connect(data->username, data->password, "google.com", 80);
    
    pthread_mutex_lock(&counter_mutex);
    if (result == 0) {
        successful_connections++;
    } else {
        failed_connections++;
    }
    pthread_mutex_unlock(&counter_mutex);
    
    if (data->semaphore) {
        sem_post(data->semaphore);
    }
    
    return NULL;
}

void run_test(int num_connections, const char *username, const char *password) {
    pthread_t *threads = malloc(num_connections * sizeof(pthread_t));
    thread_data_t *thread_data = malloc(num_connections * sizeof(thread_data_t));
    
    sem_t semaphore;
    sem_init(&semaphore, 0, MAX_CONCURRENT_THREADS);
    
    successful_connections = 0;
    failed_connections = 0;
    
    printf("Probando con %d conexiones (máx %d concurrentes)...\n", 
           num_connections, MAX_CONCURRENT_THREADS);
    
    double start_time = get_time_ms();
    
    for (int i = 0; i < num_connections; i++) {
        sem_wait(&semaphore);
        
        thread_data[i].username = username;
        thread_data[i].password = password;
        thread_data[i].thread_id = i;
        thread_data[i].semaphore = &semaphore;
        
        pthread_create(&threads[i], NULL, connection_thread, &thread_data[i]);
        
        //delay para no saturar
        if (RAMP_UP_DELAY_MS > 0 && i < num_connections - 1) {
            sleep(RAMP_UP_DELAY_MS * 1000);
        }
    }
    
    for (int i = 0; i < num_connections; i++) {
        pthread_join(threads[i], NULL);
    }
    
    double end_time = get_time_ms();
    double elapsed = (end_time - start_time) / 1000.0;
    
    double throughput = 0.0;
    if (successful_connections > 0) {
        throughput = successful_connections / elapsed;
    }
    
    double success_rate = (successful_connections * 100.0) / num_connections;
    
    printf("  Tiempo total: %.2f s\n", elapsed);
    printf("  Exitosas: %d | Fallidas: %d (%.1f%% éxito)\n", 
           successful_connections, failed_connections, success_rate);
    printf("  Throughput: %.2f req/s\n\n", throughput);
    
    FILE *f = fopen("throughput_results.csv", "a");
    if (f) {
        fprintf(f, "%d,%.2f,%.2f,%d,%d,%.2f\n", 
                num_connections, elapsed, throughput, 
                successful_connections, failed_connections, success_rate);
        fclose(f);
    }
    
    sem_destroy(&semaphore);
    free(threads);
    free(thread_data);
    
    sleep(2);
}

int main(int argc, char *argv[]) {
    const char *username = "user";
    const char *password = "pass";
    
    if (argc >= 3) {
        username = argv[1];
        password = argv[2];
    }
    
    printf("\n#### Test de Throughput vs Conexiones Concurrentes ####\n");
    printf("Servidor: socks5://%s:%s@%s:%d\n", username, password, PROXY_HOST, PROXY_PORT);
    printf("Destino: google.com:80\n");
    printf("Limite de concurrencia: %d threads simultáneos\n", MAX_CONCURRENT_THREADS);
    printf("Ramp-up: %d ms entre inicios de threads\n\n", RAMP_UP_DELAY_MS);
    
    FILE *f = fopen("throughput_results.csv", "w");
    if (f) {
        fprintf(f, "Conexiones,Tiempo(s),Throughput(req/s),Exitosas,Fallidas,TasaExito(%%)\n");
        fclose(f);
    }
    
    int test_sizes[] = {10, 25, 50, 75, 100, 150, 200, 250, 300, 400, 500};
    int num_tests = sizeof(test_sizes) / sizeof(test_sizes[0]);
    
    printf("----------------------------------------\n");
    for (int i = 0; i < num_tests; i++) {
        run_test(test_sizes[i], username, password);
    }
    
    printf("\n#### RESULTADOS FINALES ####\n");
    printf("\n%-12s %-12s %-18s %-12s %-12s %-15s\n", 
           "Conexiones", "Tiempo(s)", "Throughput(req/s)", "Exitosas", "Fallidas", "Tasa Éxito(%)");
    printf("%-12s %-12s %-18s %-12s %-12s %-15s\n", 
           "----------", "---------", "----------------", "--------", "--------", "-------------");
    
    f = fopen("throughput_results.csv", "r");
    if (f) {
        char line[256];
        fgets(line, sizeof(line), f);
        
        while (fgets(line, sizeof(line), f)) {
            int conns, success, failed;
            double time, throughput, success_rate;
            sscanf(line, "%d,%lf,%lf,%d,%d,%lf", 
                   &conns, &time, &throughput, &success, &failed, &success_rate);
            printf("%-12d %-12.2f %-18.2f %-12d %-12d %-15.1f\n", 
                   conns, time, throughput, success, failed, success_rate);
        }
        fclose(f);
    }
    
    printf("\nResultados guardados en: throughput_results.csv\n");
    printf("\nNOTA: El throughput se calcula solo con conexiones exitosas.\n");
    printf("Si la tasa de éxito es baja (<90%%), el servidor está sobrecargado.\n");
    
    return 0;
}
