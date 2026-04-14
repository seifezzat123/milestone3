#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "security.h"

#define PORT 8080
#define BUFFER_SIZE 2048

void *run_user() {
    int sock;
    struct sockaddr_in server_address;
    char buffer[BUFFER_SIZE];
    char username[BUFFER_SIZE], password[BUFFER_SIZE], credentials[BUFFER_SIZE];

    // Ask for username
    printf("Enter username: ");
    fgets(username, BUFFER_SIZE, stdin);
    username[strcspn(username, "\n")] = '\0';

    // Ask for password
    printf("Enter password: ");
    fgets(password, BUFFER_SIZE, stdin);
    password[strcspn(password, "\n")] = '\0';

    // Combine into "username password"
    snprintf(credentials, sizeof(credentials), "%s %s", username, password);

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1"); // connect to localhost

    if (connect(sock, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Step 1: Send credentials
    int cred_len = aes_encrypt(credentials, strlen(credentials));
    send(sock, credentials, cred_len, 0);

    // Step 2: Receive authentication response
    memset(buffer, 0, BUFFER_SIZE);
    int valread = read(sock, buffer, BUFFER_SIZE);
    aes_decrypt(buffer, valread);
    buffer[valread] = '\0';
    printf("Server: %s\n", buffer);

    if (strstr(buffer, "login failed")) {
        close(sock);
        return NULL;
    }

    // Step 3: Continuous command loop
    while (1) {
        printf("Enter command (or 'exit' to quit): ");
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = '\0';

        int cmd_len = aes_encrypt(buffer, strlen(buffer));
        send(sock, buffer, cmd_len, 0);

        memset(buffer, 0, BUFFER_SIZE);
        valread = read(sock, buffer, BUFFER_SIZE);
        if (valread <= 0) break;

        aes_decrypt(buffer, valread);
        buffer[valread] = '\0';
        printf("Server: %s\n", buffer);

        if (strstr(buffer, "Goodbye!") != NULL) break;
    }

    close(sock);
    return NULL;
}

int main() {
    run_user();
    return 0;
}
