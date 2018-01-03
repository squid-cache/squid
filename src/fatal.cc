/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "fatal.h"
#include "globals.h"
#include "store/Disks.h"
#include "tools.h"

static void
fatal_common(const char *message)
{
#if HAVE_SYSLOG
    syslog(LOG_ALERT, "%s", message);
#endif

    fprintf(debug_log, "FATAL: %s\n", message);

    if (Debug::log_stderr > 0 && debug_log != stderr)
        fprintf(stderr, "FATAL: %s\n", message);

    fprintf(debug_log, "Squid Cache (Version %s): Terminated abnormally.\n",
            version_string);

    fflush(debug_log);

    PrintRusage();

    dumpMallocStats();
}

void
fatal(const char *message)
{
    /* suppress secondary errors from the dying */
    shutting_down = 1;

    releaseServerSockets();

    /* XXX: this should be turned into a callback-on-fatal, or
     * a mandatory-shutdown-event or something like that.
     * - RBC 20060819
     */

    /*
     * DPW 2007-07-06
     * Call leave_suid() here to make sure that swap.state files
     * are written as the effective user, rather than root.  Squid
     * may take on root privs during reconfigure.  If squid.conf
     * contains a "Bungled" line, fatal() will be called when the
     * process still has root privs.
     */
    leave_suid();

    storeDirWriteCleanLogs(0);

    fatal_common(message);

    exit(1);
}

/* used by fatalf */
static void
fatalvf(const char *fmt, va_list args)
{
    static char fatal_str[BUFSIZ];
    vsnprintf(fatal_str, sizeof(fatal_str), fmt, args);
    fatal(fatal_str);
}

/* printf-style interface for fatal */
void
fatalf(const char *fmt,...)
{
    va_list args;
    va_start(args, fmt);
    fatalvf(fmt, args);
    va_end(args);
}

/* fatal with dumping core */
void
fatal_dump(const char *message)
{
    failure_notify = NULL;
    releaseServerSockets();

    if (message)
        fatal_common(message);

    /*
     * Call leave_suid() here to make sure that swap.state files
     * are written as the effective user, rather than root.  Squid
     * may take on root privs during reconfigure.  If squid.conf
     * contains a "Bungled" line, fatal() will be called when the
     * process still has root privs.
     */
    leave_suid();

    if (opt_catch_signals)
        storeDirWriteCleanLogs(0);

    abort();
}

