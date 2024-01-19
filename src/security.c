#include "security.h"

#include <sandbox.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syslog.h>

#include "diagnostics.h"

void security_sanity_check()
{
    if (getuid() == 0) {
        fprintf(stderr, "Do not run an HTTP server as root.\n");
        exit(EXIT_DONT_USE_ROOT);
    }
}

void security_enter_sandbox()
{
    // Surrender everything except fork()!
    const char* sandbox_cfg = "(version 1)(deny default)(allow process-fork)";

    char* priv_esc_error = NULL;
    if (sandbox_init(sandbox_cfg, 0, &priv_esc_error)) {
        diag_error_nonfatal("sandbox_init(): %s", priv_esc_error);
        sandbox_free_error(priv_esc_error);
        diag_fatal(EXIT_SANDBOX_FAILED, "Terminating because sandbox failed.");
    }
}
