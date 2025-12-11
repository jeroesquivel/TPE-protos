#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#define PROXY_HOST "127.0.0.1"
#define PROXY_PORT 1080
#define MAX_CONNECTIONS 10000
#define MAX_CONSECUTIVE_FAILURES 10
#define CONNECT_TIMEOUT_SEC 3
#define IO_TIMEOUT_SEC 3

static int connection_fds[MAX_CONNECTIONS];
static int connection_count = 0;
static int total_attempts = 0;
static int total_failures = 0;

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int set_socket_timeouts(int fd, int seconds) {
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        return -1;
    }
    return 0;
}

int socks5_handshake(int fd, const char *username, const char *password) {
    unsigned char buffer[512];
    ssize_t n;
    
    buffer[0] = 0x05;  // Version
    buffer[1] = 0x02;  // 2 methods
    buffer[2] = 0x00;  // NO_AUTH
    buffer[3] = 0x02;  // USERNAME/PASSWORD
    
    if (write(fd, buffer, 4) != 4) {
        return -1;
    }
    
    n = read(fd, buffer, 2);
    if (n != 2 || buffer[0] != 0x05) {
        return -1;
    }
    
    // Username/password auth if required
    if (buffer[1] == 0x02) {
        int ulen = strlen(username);
        int plen = strlen(password);
        
        buffer[0] = 0x01; 
        buffer[1] = (unsigned char)ulen;
        memcpy(buffer + 2, username, ulen);
        buffer[2 + ulen] = (unsigned char)plen;
        memcpy(buffer + 3 + ulen, password, plen);
        
        if (write(fd, buffer, 3 + ulen + plen) != (3 + ulen + plen)) {
            return -1;
        }
        
        n = read(fd, buffer, 2);
        if (n != 2 || buffer[0] != 0x01 || buffer[1] != 0x00) {
            return -1;
        }
    }
    
    buffer[0] = 0x05;  // Version
    buffer[1] = 0x01;  // CONNECT
    buffer[2] = 0x00;  // Reserved
    buffer[3] = 0x03;  // DOMAINNAME
    
    const char *target = "google.com";
    int target_len = strlen(target);
    buffer[4] = (unsigned char)target_len;
    memcpy(buffer + 5, target, target_len);
    buffer[5 + target_len] = 0x00;  // Port high byte
    buffer[6 + target_len] = 0x50;  // Port low byte (80)
    
    if (write(fd, buffer, 7 + target_len) != (7 + target_len)) {
        return -1;
    }
    
    n = read(fd, buffer, 10);
    if (n < 10 || buffer[0] != 0x05 || buffer[1] != 0x00) {
        return -1;
    }
    
    return 0;
}

int open_connection(const char *username, const char *password) {
    int fd;
    struct sockaddr_in addr;
    
    total_attempts++;
    
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    
    if (set_socket_timeouts(fd, IO_TIMEOUT_SEC) < 0) {
        close(fd);
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PROXY_PORT);
    inet_pton(AF_INET, PROXY_HOST, &addr.sin_addr);
    
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    
    if (socks5_handshake(fd, username, password) < 0) {
        close(fd);
        return -1;
    }
    
    set_nonblocking(fd);
    
    return fd;
}

void print_statistics() {
    printf("\n=== ESTADÍSTICAS ===\n");
    printf("Intentos totales:         %d\n", total_attempts);
    printf("Conexiones exitosas:      %d\n", connection_count);
    printf("Fallos totales:           %d\n", total_failures);
    if (total_attempts > 0) {
        printf("Tasa de éxito:            %.1f%%\n", 
               (connection_count * 100.0) / total_attempts);
    }
}

int main(int argc, char *argv[]) {
    const char *username = "user";
    const char *password = "pass";
    int consecutive_failures = 0;
    time_t start_time = time(NULL);
    
    if (argc >= 3) {
        username = argv[1];
        password = argv[2];
    }
    
    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("  Test de Máxima Cantidad de Conexiones Concurrentes\n");
    printf("═══════════════════════════════════════════════════════════\n");
    printf("Servidor:         socks5://%s:***@%s:%d\n", username, PROXY_HOST, PROXY_PORT);
    printf("Timeout conexión: %d segundos\n", CONNECT_TIMEOUT_SEC);
    printf("Timeout I/O:      %d segundos\n", IO_TIMEOUT_SEC);
    printf("Max fallos:       %d consecutivos\n", MAX_CONSECUTIVE_FAILURES);
    printf("═══════════════════════════════════════════════════════════\n\n");
    
    memset(connection_fds, -1, sizeof(connection_fds));
    
    while (connection_count < MAX_CONNECTIONS) {
        int fd = open_connection(username, password);
        
        if (fd < 0) {
            consecutive_failures++;
            total_failures++;
            
            if (consecutive_failures == 1) {
                printf("\nPrimera falla detectada en conexión #%d\n", connection_count + 1);
                printf("   Error: %s\n", strerror(errno));
            }
            
            if (consecutive_failures >= MAX_CONSECUTIVE_FAILURES) {
                printf("\n%d fallos consecutivos. Límite alcanzado.\n", 
                       MAX_CONSECUTIVE_FAILURES);
                break;
            }
            
            // Small delay before retrying
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };  // 10ms
            nanosleep(&ts, NULL);
            continue;
        }
        
        // Success - reset failure counter
        if (consecutive_failures > 0) {
            printf("Conexión #%d exitosa después de %d fallo(s)\n", 
                   connection_count + 1, consecutive_failures);
            consecutive_failures = 0;
        }
        
        connection_fds[connection_count] = fd;
        connection_count++;
        
        if (connection_count % 100 == 0) {
            time_t elapsed = time(NULL) - start_time;
            printf("✓ %d conexiones abiertas (%.1f conn/seg)\n", 
                   connection_count, 
                   elapsed > 0 ? connection_count / (double)elapsed : 0);
        }
        
        // Very small delay to avoid overwhelming the system
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };  // 1ms
        nanosleep(&ts, NULL);
    }
    
    time_t total_time = time(NULL) - start_time;
    
    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("  RESULTADOS\n");
    printf("═══════════════════════════════════════════════════════════\n");
    printf("✓ Máximo de conexiones concurrentes: %d\n", connection_count);
    printf("⏱  Tiempo total: %ld segundos\n", total_time);
    if (total_time > 0) {
        printf("📊 Velocidad promedio: %.1f conexiones/segundo\n", 
               connection_count / (double)total_time);
    }
    print_statistics();
    printf("═══════════════════════════════════════════════════════════\n");
    
    printf("\n💡 Las conexiones permanecen abiertas para verificar el límite.\n");
    printf("   Presionar Enter para cerrarlas y terminar...\n");
    getchar();
    
    printf("\n🔄 Cerrando %d conexiones...\n", connection_count);
    for (int i = 0; i < connection_count; i++) {
        if (connection_fds[i] >= 0) {
            close(connection_fds[i]);
        }
    }
    
    printf("✓ Test finalizado\n\n");
    return 0;
}