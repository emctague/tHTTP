/// tHTTP
///
/// HTTP server that tries to be obsessively secure:
/// - Uses sandboxing to drop all priveleges except fork().
/// - No parsing requests, just matching them to known paths.
/// - Serveable files are scanned and loaded once at program start.
/// - Heavy logging and detailed return codes.
/// - Tiny, auditable.
///
/// Some notes:
/// - The OSX `sandbox.h` calls are used. These are considered deprecated,
///   but are the only suitable sandboxing feature on macOS. The newer App Sandbox
///   feature doesn't appear to be something a plain C executable can opt into mid-run.
/// - The BSD `search.h` hashtable library appears to have inconsistent specification
///   between implementations - while the macOS implementation can dynamically expand
///   the table, it is heavily implied that not all implementations can or will.
/// - Socket timeout enforcement may not be strict enough to prevent a denial of service
///   based on slow read/writes (slowloris).
/// - Anything other than plain files and directories on a single drive are not permitted
///   to appear in the web root.
/// - Dotfiles (files and directories starting with a '.') will be excluded from the web root.
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sandbox.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/errno.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <search.h>
#include <fts.h>

#include "diagnostics.h"
#include "blob.h"
#include "env.h"
#include "security.h"
#include "socket.h"

typedef struct
{
    int rx_timeout;
    int tx_timeout;
    const char* notfound_route;
    int max_path_len;
} accept_loop_data;

/// Accept the next connection on the socket. Called in a loop.
void accept_next_connection(int s, accept_loop_data loop_data);

/// Handle the client connection. Called in the child process only.
void child_handle_client(struct sockaddr_in client, int ns, accept_loop_data loop_data);

/// Load web root to the HCREATE(3) hash table.
/// max_path_len_out will be populated with the longest routed path's length.
void scan_web_root(const char* path, int* max_path_len_out);

int main()
{
    security_sanity_check();
    diag_init();
    diag_notice("tHTTP STARTING UP");

#define OS_MAX_BACKLOG 128
    const int listen_backlog = get_env_integer(16, "TH_CFG_LISTEN_BACKLOG", 1, OS_MAX_BACKLOG);
    const int port = get_env_integer(80, "TH_CFG_LISTEN_PORT", 0, 65535);
    const int rx_timeout = get_env_integer(1, "TH_CFG_RX_TIMEOUT", 1, 65535);
    const int tx_timeout = get_env_integer(1, "TH_CFG_TX_TIMEOUT", 1, 65535);
    const char* web_root = get_env_str("TH_CFG_WEB_ROOT", "public_html");
    const char* notfound_route = get_env_str("TH_CFG_NOTFOUND_ROUTE", "/404.html");

    diag_info("listen backlog length (TH_CFG_LISTEN_BACKLOG): %d", listen_backlog);
    diag_info("listen port (TH_CFG_LISTEN_PORT): %d", port);
    diag_info("recieve timeout (TH_CFG_RX_TIMEOUT): %d", rx_timeout);
    diag_info("transmit timeout (TH_CFG_TX_TIMEOUT): %d", tx_timeout);
    diag_info("server root (TH_CFG_WEB_ROOT): %s", web_root);
    diag_info("404 not found route (TH_CFG_NOTFOUND_ROUTE): %s", notfound_route);

    int max_path_len = 0;
    scan_web_root(web_root, &max_path_len);

    const int s = socket_server_setup(port, listen_backlog);
    security_enter_sandbox();

    diag_info("entered sandbox.");

    const accept_loop_data loop_data = {
        .rx_timeout = rx_timeout,
        .tx_timeout = tx_timeout,
        .notfound_route = notfound_route,
        .max_path_len = max_path_len
    };

    // ReSharper disable once CppDFAEndlessLoop
    while (true) accept_next_connection(s, loop_data);
}

void accept_next_connection(const int s, const accept_loop_data loop_data)
{
    diag_debug("awaiting next connection with accept().");

    struct sockaddr_in client = {};
    socklen_t namelen = sizeof(client);
    int ns;
    if ((ns = accept(s, (struct sockaddr *) &client, &namelen)) == -1) {
        diag_error_nonfatal("accept(): %s", strerror(errno));
    } else {
        const pid_t handler_pid = fork();

        if (handler_pid < 0) {
            close(ns);
            close(s);
            diag_fatal_perror(EXIT_FORK_FAILED, "fork()");
        } else if (handler_pid == 0) {
            close(s);
            child_handle_client(client, ns, loop_data);
            exit(EXIT_OK);
        } else {
            close(ns);
        }
    }
}

void child_handle_client(struct sockaddr_in client, int ns, const accept_loop_data loop_data)
{
    diag_info("accepted new client: %s:%d", inet_ntoa(client.sin_addr),
              ntohs(client.sin_port));

    // Configure the socket with TX+RX timeouts.

    if (setsockopt(ns, SOL_SOCKET, SO_RCVTIMEO, &(struct timeval){ .tv_sec = loop_data.rx_timeout },
                   sizeof(struct timeval)) < 0) {
        diag_fatal_perror(EXIT_SETSOCKOPT_FAILED, "setsockopt()");
    }

    if (setsockopt(ns, SOL_SOCKET, SO_SNDTIMEO, &(struct timeval){ .tv_sec = loop_data.tx_timeout },
                   sizeof(struct timeval)) < 0) {
        diag_fatal_perror(EXIT_SETSOCKOPT_FAILED, "setsockopt()");
    }

    // Receive from client.
    const ssize_t max_size = loop_data.max_path_len + 5; // 'GET ' + max_path_len + ' '
    char* in_buf = socket_read(ns, 5, max_size);

    // Enforce GET request
    if (strncmp(in_buf, "GET ", 4) != 0) {
        diag_fatal(EXIT_NON_GET_REQUEST, "Got a non-GET request. Aborting.");
    }

    // Isolate the GET path.
    char* saveptr = NULL;
    char* get_path = strtok_r(in_buf + 4, " \r\n\t", &saveptr);

    // Ensure the GET path isn't.. wonky.
    if (get_path == NULL || strlen(get_path) < 1 || get_path[0] != '/') {
        diag_fatal(EXIT_WEIRD_REQUEST_PATH, "Got a weird request path. Aborting.");
    }

    // Search for the path in our routing.
    const ENTRY* found_entry = hsearch((ENTRY){ .key = get_path }, FIND);

    const char* response_status = "200 OK";

    // 404. Try to get the notfound route instead.
    if (found_entry == NULL) {
        diag_info("NOT FOUND path: %s", get_path);
        response_status = "404 NOT FOUND";
        found_entry = hsearch((ENTRY){ .key = (char *) loop_data.notfound_route }, FIND);
    }

    // 404 times two! Our notfound_route is also not found.
    if (found_entry == NULL) {
        const char* fallback_err_response =
            "HTTP/1.1 404 NOT FOUND\r\nContent-Length: 13\r\n\r\n404 NOT FOUND";
        socket_send(ns, fallback_err_response, strlen(fallback_err_response));
        shutdown(ns, SHUT_RDWR);
        close(ns);
        diag_fatal(EXIT_NOTFOUND_NOT_FOUND, "The TH_CFG_NOTFOUND_ROUTE wasn't found.");
    }

    diag_info("GET %s", get_path);

    // Okay, now we can free the stuff we read.
    free(in_buf);

    const Blob* found_blob = (Blob *) found_entry->data;

    char* message_buf = NULL;
    if (asprintf(&message_buf, "HTTP/1.1 %s\r\nContent-Length: %zu\r\n\r\n", response_status,
                 blob_get_size(found_blob)) == -1) {
        diag_fatal_perror(EXIT_MALLOC_FAILED, "asprintf()");
    }

    socket_send(ns, message_buf, strlen(message_buf));
    free(message_buf);
    socket_send(ns, blob_get_data(found_blob), blob_get_size(found_blob));

    shutdown(ns, SHUT_RDWR);
    close(ns);
}


void scan_web_root(const char* path, int* max_path_len_out)
{
    const size_t base_path_len = strlen(path);

    *max_path_len_out = 0;

    const char* path_list[] = { path, NULL };
    FTS* fts = fts_open((char * const*) path_list, FTS_PHYSICAL | FTS_COMFOLLOW | FTS_XDEV, NULL);
    if (fts == NULL) {
        diag_fatal_perror(EXIT_FTS_OPEN_FAILED, "fts_open()");
    }

    // It would seem that the macOS hcreate() implementation allows for dynamic resizing, despite
    // not mentioning this in the documentation.
    if (hcreate(1) == 0) {
        diag_fatal_perror(EXIT_HCREATE_FAILED, "hcreate()");
    }

    const char* const index_suffix = "/index.html";
    const size_t index_suffix_len = strlen(index_suffix);

    // fts_read might set errno.
    errno = 0;

    FTSENT* p;
    while ((p = fts_read(fts)) != NULL) {
        switch (p->fts_info) {
        case FTS_D:
            diag_debug("scanning path for web root: %s", p->fts_path);
            if (p->fts_name[0] == '.') {
                diag_debug("skipping dotfolder %s", p->fts_path);
                fts_set(fts, p, FTS_SKIP);
            }
            break;
        case FTS_DP:
            break;
        case FTS_F: {
            if (!S_ISREG(p->fts_statp->st_mode)) {
                diag_fatal(EXIT_FTS_UNUSUAL_FILE, "encountered a non-regular file in the web root: %s", p->fts_path);
            }

            diag_debug("found file for web root: %s", p->fts_path);

            if (p->fts_name[0] == '.') {
                diag_debug("skipping dotfile %s", p->fts_path);
                continue;
            }

            // Copy file path and remove base path.
            // Trailing slashes in the base path don't break this, surprisingly: the FTS manpage
            // specifies that the paths are simply appended, so this should always work.
            char* file_path = strdup(p->fts_path + base_path_len);
            const size_t file_path_len = strlen(file_path);

            // Is this an index.html? Strip the index.html part.
            if (file_path_len >= index_suffix_len &&
                !strncmp(&file_path[file_path_len - index_suffix_len], index_suffix, index_suffix_len)) {
                file_path[file_path_len - index_suffix_len] = '\0';

                // If we've totally emptied the file path as a result, add a trailing slash.
                if (file_path[0] == '\0') {
                    file_path[0] = '/';
                    file_path[1] = '\0';
                }
            }

            diag_debug("routing %s -> %s", file_path, p->fts_path);

            const size_t route_len = strlen(file_path);
            if (route_len > *max_path_len_out) *max_path_len_out = route_len;

            // Open file for reading
            FILE* f = fopen(p->fts_accpath, "rb");
            if (!f) {
                diag_fatal(EXIT_FOPEN_FAILED, "fopen(): %s: %s", p->fts_path, strerror(errno));
            }

            // Allocate data for file and its length
            Blob* blob = blob_new(p->fts_statp->st_size);
            if (!blob) {
                diag_fatal_perror(EXIT_MALLOC_FAILED, "malloc()");
            }

            // Read file
            const size_t num_read = fread(blob_get_data(blob), 1, blob_get_size(blob), f);
            if (num_read != p->fts_statp->st_size) {
                const int ferr = ferror(f);
                fclose(f);
                free(blob);
                free(file_path);

                if (num_read == 0 && ferr) {
                    diag_fatal_perror(EXIT_FREAD_FAILED, "fread()");
                } else {
                    diag_fatal(EXIT_FREAD_FAILED,
                               "fread(): file size was mismatched, or was changed between scan and read. expected %llu, read %zu",
                               p->fts_statp->st_size, num_read);
                }
            }
            fclose(f);

            // Save this entry.
            if (hsearch((ENTRY){ file_path, blob }, ENTER) == NULL) {
                diag_fatal(EXIT_HSEARCH_TABLE_FULL, "hsearch(): hash table is full");
            }

            break;
        }
        case FTS_SL:
        case FTS_SLNONE:
            diag_fatal(EXIT_SYMLINK_IN_WEB_ROOT, "encountered a symbolic link in the web root: %s", p->fts_path);
        case FTS_DC:
            diag_fatal(EXIT_CYCLE_IN_WEB_ROOT, "encountered a filesystem cycle in the web root: %s", p->fts_path);
        case FTS_ERR:
        case FTS_DNR:
        case FTS_NS:
            diag_fatal(EXIT_FTS_READ_FAILED, "fts_read(): FTS_ERR | FTS_DNR | FTS_NS: %s: %s", p->fts_path,
                       strerror(p->fts_errno));
        case FTS_NSOK:
        case FTS_DEFAULT:
        case FTS_DOT:
        default:
            diag_fatal(EXIT_FTS_UNUSUAL_FILE,
                       "encountered an unusual file in the web root (FTS_NSOK or FTS_DEFAULT): %s",
                       p->fts_path);
        }
    }

    if (errno != 0) {
        diag_fatal_perror(EXIT_FTS_READ_FAILED, "fts_read()");
    }

    if (fts_close(fts) == -1) {
        diag_fatal_perror(EXIT_FTS_CLOSE_FAILED, "fts_close()");
    }
}
