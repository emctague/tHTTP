#include "socket.h"

#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "diagnostics.h"

void socket_send(const int socket, const void* message, const size_t message_size)
{
    ssize_t sent = 0;
    do {
        const ssize_t bytes = send(socket, message + sent, message_size - sent, 0);
        if (bytes < 0) {
            diag_fatal_perror(EXIT_SOCKET_SEND_FAILED, "send()");
        }

        if (bytes == 0) break;

        sent += bytes;
    } while (sent < message_size);

    if (sent != message_size) {
        diag_fatal(EXIT_SOCKET_WEIRD_TX_LENGTH, "Didn't manage to send enough bytes to the client.");
    }
}

char* socket_read(const int ns, const ssize_t min_size, const ssize_t max_size)
{
    char* in_buf = malloc(max_size + 1);
    ssize_t received = 0;

    do {
        const ssize_t num_read = read(ns, in_buf + received, max_size - received);
        if (num_read < 0) {
            free(in_buf);
            close(ns);
            diag_fatal_perror(EXIT_SOCKET_READ_FAILED, "read()");
        }

        if (num_read == 0) break;

        received += num_read;
    } while (received < max_size);

    // Just in case we got a weird number of bytes somehow.
    if (received < min_size || received > max_size) {
        free(in_buf);
        close(ns);
        diag_fatal(EXIT_SOCKET_WEIRD_RX_LENGTH, "Weird receive length. Aborting.");
    }

    // Add NUL terminator
    in_buf[received] = 0;

    return in_buf;
}


int socket_server_setup(const int port, const int listen_backlog)
{
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = htonl(INADDR_ANY);

    const int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        diag_fatal_perror(EXIT_SOCKET_FAILED, "socket()");
    }

    if (bind(s, (struct sockaddr *) &server, sizeof(server)) < 0) {
        close(s);
        diag_fatal_perror(EXIT_BIND_FAILED, "bind()");
    }

    if (listen(s, listen_backlog) != 0) {
        close(s);
        diag_fatal_perror(EXIT_LISTEN_FAILED, "listen()");
    }

    diag_info("listening on: %s:%d", inet_ntoa(server.sin_addr), ntohs(server.sin_port));

    return s;
}
