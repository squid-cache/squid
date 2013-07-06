/*
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "Debug.h"
#include "fatal.h"
#include "globals.h"
#include "SwapDir.h"
#include "tools.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif

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
    /* check for store_dirs_rebuilding because fatal() is often
     * used in early initialization phases, long before we ever
     * get to the store log. */

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

    if (0 == StoreController::store_dirs_rebuilding)
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

