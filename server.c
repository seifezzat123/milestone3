#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "security.h"

#define PORT 8080
#define BUFFER_SIZE 2048  

char* authenticate(char *credentials) {
    FILE *file = fopen("users.txt", "r");
    if (!file) {
        perror("Could not open users.txt");
        return "login failed";
    }

    char line[BUFFER_SIZE];
    char file_user[BUFFER_SIZE], file_pass[BUFFER_SIZE], file_role[BUFFER_SIZE];
    char input_user[BUFFER_SIZE], input_pass[BUFFER_SIZE];

    sscanf(credentials, "%s %s", input_user, input_pass);

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = '\0';
        sscanf(line, "%s %s %s", file_user, file_pass, file_role);

        if (strcmp(file_user, input_user) == 0 && strcmp(file_pass, input_pass) == 0) {
            fclose(file);
            return strdup(file_role);
        }
    }

    fclose(file);
    return "login failed";
}

void *handle_client(void *arg) {
    int new_socket = *((int *)arg);
    free(arg);

    char buffer[BUFFER_SIZE];
    char username[BUFFER_SIZE], password[BUFFER_SIZE];

    // Step 1: Receive credentials
    memset(buffer, 0, BUFFER_SIZE);
    int valread = read(new_socket, buffer, BUFFER_SIZE);
    if (valread <= 0) {
        perror("Read failed or client disconnected");
        close(new_socket);
        pthread_exit(NULL);
    }

    aes_decrypt(buffer, valread);
    buffer[valread] = '\0';

    sscanf(buffer, "%s %s", username, password);

    char* role = authenticate(buffer);

    if (strcmp(role, "login failed") == 0) {
        char response[BUFFER_SIZE] = "login failed";
        int resp_len = aes_encrypt(response, strlen(response));
        send(new_socket, response, resp_len, 0);
        close(new_socket);
        pthread_exit(NULL);
    } else {
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response), "AUTH_SUCCESS Role:%s", role);
        int resp_len = aes_encrypt(response, strlen(response));
        send(new_socket, response, resp_len, 0);
    }

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        valread = read(new_socket, buffer, BUFFER_SIZE);
        if (valread <= 0) break;

        aes_decrypt(buffer, valread);
        buffer[valread] = '\0';

        printf("[%s][%s]: %s\n", username, role, buffer);

        char response[BUFFER_SIZE];

        if (strcmp(buffer, "exit") == 0) {
            snprintf(response, sizeof(response), "Goodbye!");
            int resp_len = aes_encrypt(response, strlen(response));
            send(new_socket, response, resp_len, 0);
            break;
        }

        if (strcmp(role, "guest") == 0) {
            if (!(strncmp(buffer, "ls", 2) == 0 || strncmp(buffer, "cat", 3) == 0)) {
                snprintf(response, sizeof(response), "Permission denied for guest");
            } else {
                FILE *fp = popen(buffer, "r");
                if (fp == NULL) {
                    snprintf(response, sizeof(response), "Failed to run command");
                } else {
                    char output[BUFFER_SIZE];
                    size_t n = fread(output, 1, sizeof(output)-1, fp);
                    output[n] = '\0';
                    pclose(fp);

                    if (strlen(output) == 0) {
                        snprintf(response, sizeof(response), "Command executed successfully: %s", buffer);
                    } else {
                        snprintf(response, sizeof(response), "%s", output);
                    }
                }
            }
        } else if (strcmp(role, "user") == 0 && strstr(buffer, "rm") != NULL) {
            snprintf(response, sizeof(response), "Permission denied for user");
        } else {
            // Execute allowed command for user/admin
            FILE *fp = popen(buffer, "r");
            if (fp == NULL) {
                snprintf(response, sizeof(response), "Failed to run command");
            } else {
                char output[BUFFER_SIZE];
                size_t n = fread(output, 1, sizeof(output)-1, fp);
                output[n] = '\0';
                pclose(fp);

                if (strlen(output) == 0) {
                    snprintf(response, sizeof(response), "Command executed successfully: %s", buffer);
                } else {
                    snprintf(response, sizeof(response), "%s", output);
                }
            }
        }

        int resp_len = aes_encrypt(response, strlen(response));
        send(new_socket, response, resp_len, 0);
    }

    close(new_socket);
    pthread_exit(NULL);
}

int main() {
    int server_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("Socket created successfully.\n");

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("Bind complete.\n");

    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("Listening on port %d...\n", PORT);

    while (1) {
        int *new_socket = malloc(sizeof(int));
        *new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (*new_socket < 0) {
            perror("Accept failed");
            free(new_socket);
            continue;
        }
        printf("New client connected.\n");

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, new_socket);
        pthread_detach(tid);
    }

    close(server_fd);
    return 0;
}
