#pragma once
#include <stddef.h>
#include <sys/types.h>

/// Establish a listening socket on port `port` with a backlog of length `listen_backlog`.
/// Can exit(EXIT_SOCKET_FAILED), exit(EXIT_BIND_FAILED), exit(EXIT_LISTEN_FAILED).
int socket_server_setup(int port, int listen_backlog);

/// Send `message_size` bytes from `message` on the socket `socket`.
/// Can exit(EXIT_SOCKET_SEND_FAILED), exit(EXIT_SOCKET_WEIRD_TX_LENGTH).
void socket_send(int socket, const void* message, size_t message_size);

/// Read up to `max_size` bytes of data from the socket. Adds a null terminator to the end and returns
/// the allocated buffer.
/// Checks to make sure the read data is at least min_size.
/// Can exit(EXIT_SOCKET_WEIRD_RX_LENGTH), exit(EXIT_SOCKET_READ_FAILED).
char* socket_read(int ns, ssize_t min_size, ssize_t max_size);
