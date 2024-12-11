#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#define close closesocket
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#include "protocol.h"

// Custom inet_ntop for Windows compatibility
const char *inet_ntop_compat(int af, const void *src, char *dst, socklen_t size) {
#ifdef _WIN32
    if (af == AF_INET) {
        struct in_addr *addr = (struct in_addr *)src;
        strncpy(dst, inet_ntoa(*addr), size);
        return dst;
    } else {
        return NULL; // IPv6 not supported in this custom implementation
    }
#else
    return inet_ntop(af, src, dst, size);
#endif
}

// Password generation functions
void generate_numeric(char *buffer, int length);
void generate_alpha(char *buffer, int length);
void generate_mixed(char *buffer, int length);
void generate_secure(char *buffer, int length);
void generate_unambiguous(char *buffer, int length);

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];
    char password[BUFFER_SIZE];
    socklen_t client_len = sizeof(client_addr);

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        exit(EXIT_FAILURE);
    }
#endif

    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
#ifdef _WIN32
        WSACleanup();
#endif
        exit(EXIT_FAILURE);
    }

    printf("Password Generator Server running on port %d...\n", SERVER_PORT);

    // Main server loop
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);
        if (n < 0) {
            perror("Receive failed");
            continue;
        }
        buffer[n] = '\0'; // Null-terminate the received message

        // Log client information using gethostbyaddr
        char client_ip[INET_ADDRSTRLEN];
        if (inet_ntop_compat(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN) == NULL) {
            fprintf(stderr, "Error converting client IP\n");
            continue;
        }

        // Use gethostbyaddr to resolve the IP to a hostname
        struct hostent *host = gethostbyaddr((const void *)&client_addr.sin_addr, sizeof(client_addr.sin_addr), AF_INET);
        if (host != NULL) {
            printf("New request from %s (%s:%d)\n", host->h_name, client_ip, ntohs(client_addr.sin_port));
        } else {
            printf("New request from %s (%s:%d)\n", client_ip, client_ip, ntohs(client_addr.sin_port));
        }

        // Parse command and length
        char command = buffer[0];
        int length = atoi(buffer + 2);

        if (length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH) {
            snprintf(password, BUFFER_SIZE, "Error: Length must be between %d and %d", MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
        } else {
            switch (command) {
                case CMD_NUMERIC:
                    generate_numeric(password, length);
                    break;
                case CMD_ALPHA:
                    generate_alpha(password, length);
                    break;
                case CMD_MIXED:
                    generate_mixed(password, length);
                    break;
                case CMD_SECURE:
                    generate_secure(password, length);
                    break;
                case CMD_UNAMBIGUOUS:
                    generate_unambiguous(password, length);
                    break;
                default:
                    snprintf(password, BUFFER_SIZE, "Error: Unknown command");
                    break;
            }
        }

        // Send response back to the client
        sendto(sockfd, password, strlen(password), 0, (struct sockaddr *)&client_addr, client_len);
    }

#ifdef _WIN32
    closesocket(sockfd);
    WSACleanup();
#else
    close(sockfd);
#endif
    return 0;
}

// Functions to generate passwords
void generate_numeric(char *buffer, int length) {
    for (int i = 0; i < length; i++) {
        buffer[i] = '0' + rand() % 10;
    }
    buffer[length] = '\0';
}

void generate_alpha(char *buffer, int length) {
    for (int i = 0; i < length; i++) {
        buffer[i] = 'a' + rand() % 26;
    }
    buffer[length] = '\0';
}

void generate_mixed(char *buffer, int length) {
    for (int i = 0; i < length; i++) {
        if (rand() % 2 == 0)
            buffer[i] = 'a' + rand() % 26;
        else
            buffer[i] = '0' + rand() % 10;
    }
    buffer[length] = '\0';
}

void generate_secure(char *buffer, int length) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    int charset_size = strlen(charset);
    for (int i = 0; i < length; i++) {
        buffer[i] = charset[rand() % charset_size];
    }
    buffer[length] = '\0';
}

void generate_unambiguous(char *buffer, int length) {
    const char charset[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz234679";
    int charset_size = strlen(charset);
    for (int i = 0; i < length; i++) {
        buffer[i] = charset[rand() % charset_size];
    }
    buffer[length] = '\0';
}
