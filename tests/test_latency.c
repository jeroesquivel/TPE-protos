#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <math.h>

#define PROXY_HOST "127.0.0.1"
#define PROXY_PORT 1080
#define NUM_SAMPLES 100

double get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec) * 1000.0 + (tv.tv_usec) / 1000.0;
}

int socks5_connect_timed(const char *username, const char *password, double *latency_ms) {
    int fd;
    struct sockaddr_in addr;
    unsigned char buffer[512];
    ssize_t n;
    
    double start_time = get_time_ms();
    
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        *latency_ms = -1;
        return -1;
    }
    
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
        *latency_ms = -1;
        return -1;
    }
    
    buffer[0] = 0x05;
    buffer[1] = 0x02;
    buffer[2] = 0x00;
    buffer[3] = 0x02;
    
    if (write(fd, buffer, 4) != 4) {
        close(fd);
        *latency_ms = -1;
        return -1;
    }
    
    n = read(fd, buffer, 2);
    if (n != 2 || buffer[0] != 0x05) {
        close(fd);
        *latency_ms = -1;
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
            *latency_ms = -1;
            return -1;
        }
        
        n = read(fd, buffer, 2);
        if (n != 2 || buffer[1] != 0x00) {
            close(fd);
            *latency_ms = -1;
            return -1;
        }
    }
    
    buffer[0] = 0x05;
    buffer[1] = 0x01;
    buffer[2] = 0x00;
    buffer[3] = 0x03;
    
    const char *target = "google.com";
    int target_len = strlen(target);
    buffer[4] = (unsigned char)target_len;
    memcpy(buffer + 5, target, target_len);
    buffer[5 + target_len] = 0x00;
    buffer[6 + target_len] = 0x50;
    
    if (write(fd, buffer, 7 + target_len) != (7 + target_len)) {
        close(fd);
        *latency_ms = -1;
        return -1;
    }
    
    n = read(fd, buffer, 10);
    
    double end_time = get_time_ms();
    *latency_ms = end_time - start_time;
    
    close(fd);
    
    if (n < 10 || buffer[0] != 0x05 || buffer[1] != 0x00) {
        return -1;
    }
    
    return 0;
}

int compare_double(const void *a, const void *b) {
    double diff = *(double*)a - *(double*)b;
    return (diff > 0) - (diff < 0);
}

int main(int argc, char *argv[]) {
    const char *username = "user";
    const char *password = "pass";
    
    if (argc >= 3) {
        username = argv[1];
        password = argv[2];
    }
    
    printf("#### Test de Latencia Promedio ####\n");
    printf("Servidor: socks5://%s:%s@%s:%d\n", username, password, PROXY_HOST, PROXY_PORT);
    printf("Muestras: %d\n\n", NUM_SAMPLES);
    
    double *latencies = malloc(NUM_SAMPLES * sizeof(double));
    int successful = 0;
    int failed = 0;
    double sum = 0.0;
    
    printf("Ejecutando %d conexiones secuenciales...\n", NUM_SAMPLES);
    
    for (int i = 0; i < NUM_SAMPLES; i++) {
        double latency;
        int result = socks5_connect_timed(username, password, &latency);
        
        if (result == 0 && latency > 0) {
            latencies[successful] = latency;
            sum += latency;
            successful++;
            
            if ((i + 1) % 10 == 0) {
                printf("Completadas: %d/%d\n", i + 1, NUM_SAMPLES);
            }
        } else {
            failed++;
        }
        
        usleep(10000);
    }
    
    if (successful == 0) {
        printf("\nTodas las conexiones fallaron\n");
        free(latencies);
        return 1;
    }
    
    qsort(latencies, successful, sizeof(double), compare_double);
    
    double avg = sum / successful;
    double min = latencies[0];
    double max = latencies[successful - 1];
    double median = latencies[successful / 2];
    double p95 = latencies[(int)(successful * 0.95)];
    double p99 = latencies[(int)(successful * 0.99)];
    
    double variance = 0.0;
    for (int i = 0; i < successful; i++) {
        double diff = latencies[i] - avg;
        variance += diff * diff;
    }
    double stddev = sqrt(variance / successful);
    
    printf("\n#### RESULTADOS ####\n");
    printf("Conexiones exitosas: %d/%d (%.1f%%)\n", 
           successful, NUM_SAMPLES, (successful * 100.0) / NUM_SAMPLES);
    printf("Conexiones fallidas: %d\n\n", failed);
    
    printf("Latencia (tiempo completo de handshake SOCKS5 + CONNECT):\n");
    printf("  Promedio:  %.2f ms\n", avg);
    printf("  Mediana:   %.2f ms\n", median);
    printf("  Mínima:    %.2f ms\n", min);
    printf("  Máxima:    %.2f ms\n", max);
    printf("  Desv. Est: %.2f ms\n", stddev);
    printf("  P95:       %.2f ms\n", p95);
    printf("  P99:       %.2f ms\n", p99);
    
    FILE *f = fopen("latency_results.csv", "w");
    if (f) {
        fprintf(f, "Sample,Latency(ms)\n");
        for (int i = 0; i < successful; i++) {
            fprintf(f, "%d,%.2f\n", i + 1, latencies[i]);
        }
        fclose(f);
        printf("\nResultados guardados en: latency_results.csv\n");
    }
    
    free(latencies);
    return 0;
}
