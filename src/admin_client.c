#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define htobe16(x) OSSwapHostToBigInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#else
#define _DEFAULT_SOURCE
#include <endian.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define ADMIN_VERSION 0x01

#define CMD_GET_METRICS 0x01
#define CMD_LIST_USERS 0x02
#define CMD_ADD_USER 0x03
#define CMD_DEL_USER 0x04
#define CMD_LIST_CONNECTIONS 0x05
#define CMD_CHANGE_PASSWORD 0x06
#define CMD_CHANGE_ROLE 0x07

#define STATUS_OK 0x00
#define STATUS_ERROR 0x01
#define STATUS_INVALID_CMD 0x02
#define STATUS_USER_EXISTS 0x03
#define STATUS_USER_NOT_FOUND 0x04
#define STATUS_PERMISSION_DENIED 0x05
#define STATUS_INVALID_ARGS 0x06
#define STATUS_AUTH_FAILED 0x07

static int connect_to_server(const char *host, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sockfd);
        return -1;
    }
    
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

static int authenticate(int sockfd, const char *username, const char *password) {
    uint8_t buffer[512];
    size_t pos = 0;
    
    buffer[pos++] = ADMIN_VERSION;
    buffer[pos++] = (uint8_t)strlen(username);
    memcpy(buffer + pos, username, strlen(username));
    pos += strlen(username);
    buffer[pos++] = (uint8_t)strlen(password);
    memcpy(buffer + pos, password, strlen(password));
    pos += strlen(password);
    
    if (send(sockfd, buffer, pos, 0) != (ssize_t)pos) {
        perror("send auth");
        return -1;
    }
    
    uint8_t response[2];
    if (recv(sockfd, response, 2, 0) != 2) {
        fprintf(stderr, "Failed to receive auth response\n");
        return -1;
    }
    
    if (response[1] != STATUS_OK) {
        fprintf(stderr, "Authentication failed\n");
        return -1;
    }
    
    return 0;
}

static int send_command(int sockfd, uint8_t command, const uint8_t *data, uint16_t data_len) {
    uint8_t header[4];
    header[0] = ADMIN_VERSION;
    header[1] = command;
    uint16_t len_net = htons(data_len);
    memcpy(header + 2, &len_net, 2);
    
    if (send(sockfd, header, 4, 0) != 4) {
        perror("send header");
        return -1;
    }
    
    if (data_len > 0) {
        if (send(sockfd, data, data_len, 0) != data_len) {
            perror("send data");
            return -1;
        }
    }
    
    return 0;
}

static int recv_response(int sockfd, uint8_t *status, uint8_t *data, uint16_t *data_len) {
    uint8_t header[4];
    ssize_t n = recv(sockfd, header, 4, 0);
    if (n != 4) {
        fprintf(stderr, "Failed to receive response header\n");
        return -1;
    }
    
    *status = header[1];
    uint16_t len_net;
    memcpy(&len_net, header + 2, 2);
    *data_len = ntohs(len_net);
    
    if (*data_len > 0) {
        size_t received = 0;
        while (received < *data_len) {
            n = recv(sockfd, data + received, *data_len - received, 0);
            if (n <= 0) {
                fprintf(stderr, "Failed to receive response data\n");
                return -1;
            }
            received += n;
        }
    }
    
    return 0;
}

static void cmd_metrics(int sockfd) {
    if (send_command(sockfd, CMD_GET_METRICS, NULL, 0) < 0) {
        return;
    }
    
    uint8_t status;
    uint8_t data[8192];
    uint16_t data_len;
    
    if (recv_response(sockfd, &status, data, &data_len) < 0) {
        return;
    }
    
    if (status != STATUS_OK) {
        fprintf(stderr, "Command failed with status %d\n", status);
        return;
    }
    
    if (data_len < 32) {
        fprintf(stderr, "Invalid response length\n");
        return;
    }
    
    uint64_t total_conn, current_conn, bytes_trans, start_time;
    memcpy(&total_conn, data, 8);
    memcpy(&current_conn, data + 8, 8);
    memcpy(&bytes_trans, data + 16, 8);
    memcpy(&start_time, data + 24, 8);
    
    total_conn = be64toh(total_conn);
    current_conn = be64toh(current_conn);
    bytes_trans = be64toh(bytes_trans);
    start_time = be64toh(start_time);
    
    printf("=== METRICS ===\n");
    printf("Total connections: %llu\n", (unsigned long long)total_conn);
    printf("Current connections: %llu\n", (unsigned long long)current_conn);
    printf("Bytes transferred: %llu\n", (unsigned long long)bytes_trans);
    printf("Server start time: %llu\n", (unsigned long long)start_time);
}

static void cmd_users(int sockfd) {
    if (send_command(sockfd, CMD_LIST_USERS, NULL, 0) < 0) {
        return;
    }
    
    uint8_t status;
    uint8_t data[8192];
    uint16_t data_len;
    
    if (recv_response(sockfd, &status, data, &data_len) < 0) {
        return;
    }
    
    if (status != STATUS_OK) {
        fprintf(stderr, "Command failed with status %d\n", status);
        return;
    }
    
    printf("=== USERS ===\n");
    
    uint8_t count = data[0];
    printf("Total: %d\n", count);
    
    size_t ptr = 1;
    for (int i = 0; i < count; i++) {
        if (ptr >= data_len) break;
        
        uint8_t username_len = data[ptr++];
        if (ptr + username_len > data_len) break;
        
        char username[256];
        memcpy(username, data + ptr, username_len);
        username[username_len] = '\0';
        ptr += username_len;
        
        if (ptr + 16 > data_len) break;
        
        uint64_t bytes_trans, total_conn;
        memcpy(&bytes_trans, data + ptr, 8);
        ptr += 8;
        memcpy(&total_conn, data + ptr, 8);
        ptr += 8;
        
        bytes_trans = be64toh(bytes_trans);
        total_conn = be64toh(total_conn);
        
        printf("  - %s: %llu connections, %llu bytes\n", 
               username, (unsigned long long)total_conn, (unsigned long long)bytes_trans);
    }
}

static void cmd_add_user(int sockfd, const char *username, const char *password) {
    uint8_t data[512];
    size_t pos = 0;
    
    size_t username_len = strlen(username);
    size_t password_len = strlen(password);
    
    memcpy(data + pos, username, username_len);
    pos += username_len;
    data[pos++] = '\0';
    memcpy(data + pos, password, password_len);
    pos += password_len;
    data[pos++] = '\0';
    
    if (send_command(sockfd, CMD_ADD_USER, data, pos) < 0) {
        return;
    }
    
    uint8_t status;
    uint8_t response[8192];
    uint16_t response_len;
    
    if (recv_response(sockfd, &status, response, &response_len) < 0) {
        return;
    }
    
    printf("=== ADD USER: %s ===\n", username);
    if (status == STATUS_OK) {
        printf("User added successfully\n");
    } else if (status == STATUS_USER_EXISTS) {
        printf("User already exists\n");
    } else if (status == STATUS_PERMISSION_DENIED) {
        printf("Permission denied (admin role required)\n");
    } else {
        printf("Error: status=%d\n", status);
    }
}

static void cmd_del_user(int sockfd, const char *username) {
    size_t username_len = strlen(username);
    uint8_t data[256];
    
    memcpy(data, username, username_len);
    data[username_len] = '\0';
    
    if (send_command(sockfd, CMD_DEL_USER, data, username_len + 1) < 0) {
        return;
    }
    
    uint8_t status;
    uint8_t response[8192];
    uint16_t response_len;
    
    if (recv_response(sockfd, &status, response, &response_len) < 0) {
        return;
    }
    
    printf("=== DELETE USER: %s ===\n", username);
    if (status == STATUS_OK) {
        printf("User deleted successfully\n");
    } else if (status == STATUS_USER_NOT_FOUND) {
        printf("User not found\n");
    } else if (status == STATUS_PERMISSION_DENIED) {
        printf("Permission denied (admin role required)\n");
    } else {
        printf("Error: status=%d\n", status);
    }
}

static void cmd_connections(int sockfd) {
    if (send_command(sockfd, CMD_LIST_CONNECTIONS, NULL, 0) < 0) {
        return;
    }
    
    uint8_t status;
    uint8_t data[8192];
    uint16_t data_len;
    
    if (recv_response(sockfd, &status, data, &data_len) < 0) {
        return;
    }
    
    if (status != STATUS_OK) {
        fprintf(stderr, "Command failed with status %d\n", status);
        return;
    }
    
    printf("=== CONNECTIONS ===\n");
    
    if (data_len == 0) {
        printf("No connections logged\n");
        return;
    }
    
    uint8_t count = data[0];
    printf("Total: %d\n", count);
    
    size_t ptr = 1;
    for (int i = 0; i < count; i++) {
        if (ptr >= data_len) break;
        
        uint8_t username_len = data[ptr++];
        if (ptr + username_len > data_len) break;
        
        char username[256];
        memcpy(username, data + ptr, username_len);
        username[username_len] = '\0';
        ptr += username_len;
        
        if (ptr >= data_len) break;
        uint8_t dest_len = data[ptr++];
        if (ptr + dest_len > data_len) break;
        
        char destination[256];
        memcpy(destination, data + ptr, dest_len);
        destination[dest_len] = '\0';
        ptr += dest_len;
        
        if (ptr + 10 > data_len) break;
        
        uint16_t port_val;
        memcpy(&port_val, data + ptr, 2);
        port_val = be16toh(port_val);
        ptr += 2;
        
        uint64_t timestamp;
        memcpy(&timestamp, data + ptr, 8);
        timestamp = be64toh(timestamp);
        ptr += 8;
        
        time_t ts = (time_t)timestamp;
        struct tm *tm_info = localtime(&ts);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
        
        printf("  - %s -> %s:%u at %s\n", username, destination, port_val, time_str);
    }
}

static void cmd_change_password(int sockfd, const char *username, const char *new_password) {
    uint8_t data[512];
    size_t pos = 0;
    
    size_t username_len = strlen(username);
    size_t password_len = strlen(new_password);
    
    memcpy(data + pos, username, username_len);
    pos += username_len;
    data[pos++] = '\0';
    memcpy(data + pos, new_password, password_len);
    pos += password_len;
    data[pos++] = '\0';
    
    if (send_command(sockfd, CMD_CHANGE_PASSWORD, data, pos) < 0) {
        return;
    }
    
    uint8_t status;
    uint8_t response[8192];
    uint16_t response_len;
    
    if (recv_response(sockfd, &status, response, &response_len) < 0) {
        return;
    }
    
    printf("=== CHANGE PASSWORD: %s ===\n", username);
    if (status == STATUS_OK) {
        printf("Password changed successfully\n");
    } else if (status == STATUS_USER_NOT_FOUND) {
        printf("User not found\n");
    } else if (status == STATUS_PERMISSION_DENIED) {
        printf("Permission denied (admin role required)\n");
    } else {
        printf("Error: status=%d\n", status);
    }
}

static void cmd_change_role(int sockfd, const char *username, const char *role) {
    uint8_t data[512];
    size_t pos = 0;
    
    size_t username_len = strlen(username);
    size_t role_len = strlen(role);
    
    memcpy(data + pos, username, username_len);
    pos += username_len;
    data[pos++] = '\0';
    memcpy(data + pos, role, role_len);
    pos += role_len;
    data[pos++] = '\0';
    
    if (send_command(sockfd, CMD_CHANGE_ROLE, data, pos) < 0) {
        return;
    }
    
    uint8_t status;
    uint8_t response[8192];
    uint16_t response_len;
    
    if (recv_response(sockfd, &status, response, &response_len) < 0) {
        return;
    }
    
    printf("=== CHANGE ROLE: %s ===\n", username);
    if (status == STATUS_OK) {
        printf("Role changed successfully to '%s'\n", role);
    } else if (status == STATUS_USER_NOT_FOUND) {
        printf("User not found\n");
    } else if (status == STATUS_PERMISSION_DENIED) {
        printf("Permission denied (admin role required)\n");
    } else if (status == STATUS_INVALID_ARGS) {
        printf("Invalid role (must be 'admin' or 'user')\n");
    } else {
        printf("Error: status=%d\n", status);
    }
}

static void print_usage(const char *prog) {
    printf("Usage: %s -h <host> -p <port> -u <username> -P <password> COMMAND [ARGS]\n", prog);
    printf("\nOptions:\n");
    printf("  -h <host>      Admin server host (default: 127.0.0.1)\n");
    printf("  -p <port>      Admin server port (default: 8080)\n");
    printf("  -u <username>  Username for authentication\n");
    printf("  -P <password>  Password for authentication\n");
    printf("\nCommands:\n");
    printf("  metrics                          Show server metrics\n");
    printf("  users                            List all users\n");
    printf("  add <user> <pass>                Add a new user (admin only)\n");
    printf("  del <user>                       Delete a user (admin only)\n");
    printf("  conns                            List recent connections\n");
    printf("  change-password <user> <pass>    Change user password (admin only)\n");
    printf("  change-role <user> <admin|user>  Change user role (admin only)\n");
    printf("\nExamples:\n");
    printf("  %s -u admin -P 1234 metrics\n", prog);
    printf("  %s -u admin -P 1234 add john secret123\n", prog);
    printf("  %s -u admin -P 1234 change-role john admin\n", prog);
}

int main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    int port = 8080;
    const char *username = NULL;
    const char *password = NULL;
    
    int opt;
    while ((opt = getopt(argc, argv, "h:p:u:P:")) != -1) {
        switch (opt) {
            case 'h':
                host = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'u':
                username = optarg;
                break;
            case 'P':
                password = optarg;
                break;
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    
    if (username == NULL || password == NULL) {
        fprintf(stderr, "Error: username and password are required\n\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    
    if (optind >= argc) {
        fprintf(stderr, "Error: command required\n\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    
    const char *command = argv[optind];
    
    int sockfd = connect_to_server(host, port);
    if (sockfd < 0) {
        exit(EXIT_FAILURE);
    }
    
    if (authenticate(sockfd, username, password) < 0) {
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    if (strcmp(command, "metrics") == 0) {
        cmd_metrics(sockfd);
    } else if (strcmp(command, "users") == 0) {
        cmd_users(sockfd);
    } else if (strcmp(command, "add") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Error: 'add' requires username and password\n");
            print_usage(argv[0]);
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        cmd_add_user(sockfd, argv[optind + 1], argv[optind + 2]);
    } else if (strcmp(command, "del") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: 'del' requires username\n");
            print_usage(argv[0]);
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        cmd_del_user(sockfd, argv[optind + 1]);
    } else if (strcmp(command, "conns") == 0) {
        cmd_connections(sockfd);
    } else if (strcmp(command, "change-password") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Error: 'change-password' requires username and new password\n");
            print_usage(argv[0]);
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        cmd_change_password(sockfd, argv[optind + 1], argv[optind + 2]);
    } else if (strcmp(command, "change-role") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Error: 'change-role' requires username and role\n");
            print_usage(argv[0]);
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        cmd_change_role(sockfd, argv[optind + 1], argv[optind + 2]);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    close(sockfd);
    return 0;
}
