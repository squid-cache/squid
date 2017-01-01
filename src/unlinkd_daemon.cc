/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section --    Unlink Daemon */

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

