#pragma once
#include <stdnoreturn.h>

/// All exit / return codes tHTTP will ever return, and their reasons.
enum tHTTPError
{
    /// OK: No Error.
    /// Should only be returned from child processes as tHTTP never stops itself.
    EXIT_OK = 0,
    /// socket() call failed, unable to establish the server socket.
    EXIT_SOCKET_FAILED = 1,
    /// bind() call failed, unable to bind the server socket to an address.
    EXIT_BIND_FAILED = 2,
    /// listen() call failed, unable to listen for connections to the server socket.
    EXIT_LISTEN_FAILED = 3,
    /// sandbox_init() call failed, unable to surrender priveleges and become sandboxed.
    EXIT_SANDBOX_FAILED = 4,
    /// fork() failed, unable to spawn child process to handle a request.
    EXIT_FORK_FAILED = 5,
    /// An environment variable used to configure the server was invalid.
    EXIT_INVALID_NUMERIC_ENV_VAR = 6,
    /// Attempted to run the server as root.
    EXIT_DONT_USE_ROOT = 7,
    /// fts_open() call failed, unable to scan the directory.
    EXIT_FTS_OPEN_FAILED = 8,
    /// fts_close() call failed, unable to stop the scan and return to our original pwd.
    EXIT_FTS_CLOSE_FAILED = 9,
    /// fts_read() call failed, we couldn't scan the whole directory.
    EXIT_FTS_READ_FAILED = 10,
    /// There was a symbolic link in the web root.
    EXIT_SYMLINK_IN_WEB_ROOT = 11,
    /// fts_read() call failed in some internal manner.
    EXIT_FTS_READ_FAILED_ERR_DNR = 12,
    /// fts_read() found a weird or special sort of file.
    EXIT_FTS_UNUSUAL_FILE = 13,
    /// There was a cyclic path in the web root.
    EXIT_CYCLE_IN_WEB_ROOT = 14,
    /// hcreate() call failed, unable to create hash table.
    EXIT_HCREATE_FAILED = 15,
    /// fopen() call failed, couldn't open a file for reading.
    EXIT_FOPEN_FAILED = 16,
    /// malloc() call failed, couldn't allocate memory for a file.
    EXIT_MALLOC_FAILED = 17,
    /// fread() call failed or didn't read enough data.
    EXIT_FREAD_FAILED = 18,
    /// The hash table was filled up - more files than we thought!
    EXIT_HSEARCH_TABLE_FULL = 19,
    /// setsockopt() call failed, couldn't configure the client socket.
    EXIT_SETSOCKOPT_FAILED = 20,
    /// read() call failed, unable to recieve from client.
    EXIT_SOCKET_READ_FAILED = 21,
    /// A client handler got a non-GET request.
    EXIT_NON_GET_REQUEST = 22,
    /// A client handler read a weird / un-handleable number of bytes.
    EXIT_SOCKET_WEIRD_RX_LENGTH = 23,
    /// A client sent a weird request path.
    EXIT_WEIRD_REQUEST_PATH = 24,
    /// The 404 route wasn't found, so we had to send a default.
    EXIT_NOTFOUND_NOT_FOUND = 25,
    /// send() call failed, unable to send to client.
    EXIT_SOCKET_SEND_FAILED = 26,
    /// A client handler sent a weird number of bytes!?
    EXIT_SOCKET_WEIRD_TX_LENGTH = 27
};

/// Initialize logging / diagnostics system.
void diag_init();

/// Log an error and terminate the current process with the given tHTTPError.
__attribute__((format(printf, 2, 3)))
noreturn void diag_fatal(enum tHTTPError error, const char* format, ...);

/// Log an error using the current `errno` and some context,
/// and terminate the current process with the given tHTTPError.
noreturn void diag_fatal_perror(enum tHTTPError error, const char* context);

/// Log notable basic information.
__attribute__((format(printf, 1, 2)))
void diag_notice(const char* format, ...);

/// Log non-fatal errors.
__attribute__((format(printf, 1, 2)))
void diag_error_nonfatal(const char* format, ...);

/// Log basic information.
__attribute__((format(printf, 1, 2)))
void diag_info(const char* format, ...);

/// Log debug information.
__attribute__((format(printf, 1, 2)))
void diag_debug(const char* format, ...);

/// Log warning information.
__attribute__((format(printf, 1, 2)))
void diag_warn(const char* format, ...);
