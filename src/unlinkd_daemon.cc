/*
 * DEBUG: section --    Unlink Daemon
 * AUTHOR: Duane Wessels
 *
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

#define SQUID_HELPER 1

#include "squid.h"

#if HAVE_PATHS_H
#include <paths.h>
#endif

/**
 \defgroup unlinkd unlinkd
 \ingroup ExternalPrograms
 \par
    The unlink(2) system call can cause a process to block
    for a significant amount of time.  Therefore we do not want
    to make unlink() calls from Squid.  Instead we pass them
    to this external process.
 */

/// \ingroup unlinkd
#define UNLINK_BUF_LEN 1024

/**
 \ingroup unlinkd
 \par This is the unlinkd external process.
 *
 \par
 *    unlinkd receives the full path of any files to be removed
 *    from stdin, each on its own line.
 *
 \par
 *    The results for each file are printed to stdout in the order
 *    they were received
 *
 \param argc Ignored.
 \param argv Ignored.
 \retval ERR An error occured removing the file.
 \retval OK  The file has been removed.
 */
int
main(int argc, char *argv[])
{
    char buf[UNLINK_BUF_LEN];
    char *t;
    int x;
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    close(2);
    if (open(_PATH_DEVNULL, O_RDWR) < 0) {
        ; // the irony of having to close(2) earlier is that we cannot report this failure.
    }

    while (fgets(buf, sizeof(buf), stdin)) {
        if ((t = strchr(buf, '\n')))
            *t = '\0';
        x = unlink(buf);
        if (x < 0)
            printf("ERR\n");
        else
            printf("OK\n");
    }

    return 0;
}
