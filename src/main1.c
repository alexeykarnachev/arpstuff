#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int BROADCAST_PORT = 1900;

void broadcast_message(char* message) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    int broadcast = 1;
    setsockopt(
        sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)
    );

    // Set up the broadcast address
    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(BROADCAST_PORT);
    broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");

    // Send the message to the broadcast address
    int send_res = sendto(
        sock,
        message,
        strlen(message),
        0,
        (struct sockaddr*)&broadcast_addr,
        sizeof(broadcast_addr)
    );

    if (send_res < 0) {
        perror("sendto");
        exit(1);
    }

    close(sock);
}

int receive_responses(char* message, char** responses, int max_responses) {
    socklen_t addr_len;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(BROADCAST_PORT);
    local_addr.sin_addr.s_addr = INADDR_ANY;
    int bind_res = bind(
        sock, (struct sockaddr*)&local_addr, sizeof(local_addr)
    );
    if (bind_res < 0) {
        perror("bind");
        close(sock);
        exit(1);
    }

    // Set a timeout on the socket so we don't block forever
    // struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    // if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    // {
    //     perror("setsockopt");
    //     close(sock);
    //     exit(1);
    // }

    // Receive responses until we reach the maximum number or timeout
    int num_responses = 0;
    char buffer[1024];
    struct sockaddr_in remote_addr;
    while (num_responses < max_responses) {
        printf("%d/%d\n", num_responses, max_responses);
        addr_len = sizeof(remote_addr);
        memset(buffer, 0, sizeof(buffer));
        int num_bytes = recvfrom(
            sock,
            buffer,
            1024 - 1,
            0,
            (struct sockaddr*)&remote_addr,
            &addr_len
        );
        if (num_bytes < 0) {
            // Timeout or error occurred, stop receiving
            break;
        } else {
            // Check if the message matches our broadcast message
            if (strncmp(buffer, message, strlen(message)) == 0) {
                // Add the remote address to our list of responses
                char* response = inet_ntoa(remote_addr.sin_addr);
                responses[num_responses++] = strdup(response);
            }
        }
    }

    close(sock);

    return num_responses;
}

void main(void) {
    char* message = "HELLO WORLD HELLO WORLD";

    broadcast_message(message);
    char* responses[128];
    int n_responses = receive_responses(message, responses, 128);
    printf("%d\n", n_responses);
}
