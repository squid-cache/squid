/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section --    Unlink Daemon */

#define SQUID_HELPER 1

#include "squid.h"

#include <iostream>
#include <cstdio>
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
 \retval ERR An error occurred removing the file.
 \retval OK  The file has been removed.
 */
int
main(int, char *[])
{
    std::string sbuf;
    close(2);
    if (open(_PATH_DEVNULL, O_RDWR) < 0) {
        ; // the irony of having to close(2) earlier is that we cannot report this failure.
    }
    while (getline(std::cin, sbuf)) {
        // tailing newline is removed by getline
        const int rv = remove(sbuf.c_str());
        if (rv < 0)
            std::cout << "ERR" << std::endl; // endl flushes
        else
            std::cout << "OK" << std::endl;
    }

    return 0;
}

