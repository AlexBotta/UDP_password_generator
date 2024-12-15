#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

void print_help_menu() {
    printf("Password Generator Help Menu\n");
    printf("Commands:\n");
    printf(" h        : show this help menu\n");
    printf(" n LENGTH : generate numeric password (digits only)\n");
    printf(" a LENGTH : generate alphabetic password (lowercase letters)\n");
    printf(" m LENGTH : generate mixed password (lowercase letters and numbers)\n");
    printf(" s LENGTH : generate secure password (uppercase, lowercase, numbers, symbols)\n");
    printf(" u LENGTH : generate unambiguous secure password (no similar-looking characters)\n");
    printf(" q        : quit application\n\n");
    printf(" LENGTH must be between %d and %d characters\n\n", MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
    printf(" Ambiguous characters excluded in 'u' option:\n");
    printf(" 0 O o (zero and letters O)\n");
    printf(" 1 l I i (one and letters l, I)\n");
    printf(" 2 Z z (two and letter Z)\n");
    printf(" 5 S s (five and letter S)\n");
    printf(" 8 B (eight and letter B)\n");
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE];

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

#ifdef _WIN32
    // Use inet_addr instead of inet_pton for Windows compatibility
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);
    if (server_addr.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "Invalid server address\n");
        close(sockfd);
        WSACleanup();
        exit(EXIT_FAILURE);
    }
#else
    if (inet_pton(AF_INET, SERVER_ADDRESS, &server_addr.sin_addr) <= 0) {
        perror("Invalid server address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
#endif

    printf("Password Generator Client\n");
    print_help_menu();

    while (1) {
        printf("> ");
        if (!fgets(buffer, BUFFER_SIZE, stdin)) break;

        buffer[strcspn(buffer, "\n")] = '\0'; // Remove newline character

        if (strcmp(buffer, "h") == 0) {
            print_help_menu();
            continue;
        }

        if (buffer[0] == CMD_QUIT) break;

        // Send request
        sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));

        // Receive response
        int n = recvfrom(sockfd, response, BUFFER_SIZE, 0, NULL, NULL);
        if (n < 0) {
            perror("Receive failed");
            continue;
        }
        response[n] = '\0';

        printf("Password: %s\n", response);
    }


#ifdef _WIN32
    closesocket(sockfd);
    WSACleanup();
#else
    close(sockfd);
#endif
    return 0;
}
