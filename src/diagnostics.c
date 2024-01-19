#include "diagnostics.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/syslog.h>

void diag_init()
{
    openlog("tHTTP", LOG_PERROR | LOG_PID | LOG_CONS, LOG_DAEMON);
}

void diag_fatal(const enum tHTTPError error, const char* format, ...)
{
    va_list aptr;
    va_start(aptr, format);
    vsyslog(LOG_DAEMON | LOG_ERR, format, aptr);
    va_end(aptr);

    exit(error);
}

void diag_fatal_perror(const enum tHTTPError error, const char* context)
{
    diag_fatal(error, "%s: %s", context, strerror(errno));
}

void diag_notice(const char* format, ...)
{
    va_list aptr;
    va_start(aptr, format);
    vsyslog(LOG_DAEMON | LOG_NOTICE, format, aptr);
    va_end(aptr);
}

void diag_error_nonfatal(const char* format, ...)
{
    va_list aptr;
    va_start(aptr, format);
    vsyslog(LOG_DAEMON | LOG_ERR, format, aptr);
    va_end(aptr);
}

void diag_info(const char* format, ...)
{
    va_list aptr;
    va_start(aptr, format);
    vsyslog(LOG_DAEMON | LOG_INFO, format, aptr);
    va_end(aptr);
}

void diag_debug(const char* format, ...)
{
    va_list aptr;
    va_start(aptr, format);
    vsyslog(LOG_DAEMON | LOG_DEBUG, format, aptr);
    va_end(aptr);
}

void diag_warn(const char* format, ...)
{
    va_list aptr;
    va_start(aptr, format);
    vsyslog(LOG_DAEMON | LOG_WARNING, format, aptr);
    va_end(aptr);
}
