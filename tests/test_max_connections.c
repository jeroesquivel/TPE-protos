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

static int connection_fds[MAX_CONNECTIONS];
static int connection_count = 0;

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
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
    
    // CONNECT request a google.com:80
    buffer[0] = 0x05;  // Version
    buffer[1] = 0x01;  // CONNECT
    buffer[2] = 0x00;  // Reserved
    buffer[3] = 0x03;  // DOMAINNAME
    
    const char *target = "google.com";
    int target_len = strlen(target);
    buffer[4] = (unsigned char)target_len;
    memcpy(buffer + 5, target, target_len);
    buffer[5 + target_len] = 0x00;  
    buffer[6 + target_len] = 0x50;  
    
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
    
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
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
    
    //poner en modo no bloqueante para mantenerlo abierto
    set_nonblocking(fd);
    
    return fd;
}

int main(int argc, char *argv[]) {
    const char *username = "user";
    const char *password = "pass";
    
    if (argc >= 3) {
        username = argv[1];
        password = argv[2];
    }
    
    printf("\n#### Test de Máxima Cantidad de Conexiones Concurrentes ####\n");
    printf("Servidor: socks5://%s:%s@%s:%d\n", username, password, PROXY_HOST, PROXY_PORT);
    printf("Abriendo conexiones sin cerrarlas hasta que falle...\n\n");
    
    memset(connection_fds, -1, sizeof(connection_fds));
    
    while (connection_count < MAX_CONNECTIONS) {
        int fd = open_connection(username, password);
        
        if (fd < 0) {
            printf("\nFalló al intentar abrir conexión #%d\n", connection_count + 1);
            printf("   Error: %s\n", strerror(errno));
            break;
        }
        
        connection_fds[connection_count] = fd;
        connection_count++;
        
        if (connection_count % 50 == 0) {
            printf("%d conexiones abiertas...\n", connection_count);
        }
        
        struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = 1000000
        };
        nanosleep(&ts, NULL);
    }
    
    printf("\n#### RESULTADOS ####\n");
    printf("Maximo de conexiones concurrentes alcanzado: %d\n", connection_count);
    printf("\nPresionar Enter para cerrar todas las conexiones y terminar...");
    getchar();
    
    printf("Cerrando todas las conexiones...\n");
    for (int i = 0; i < connection_count; i++) {
        if (connection_fds[i] >= 0) {
            close(connection_fds[i]);
        }
    }
    
    printf("Test finalizado\n");
    return 0;
}
