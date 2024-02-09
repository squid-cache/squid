/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "comm.h"
#include "debug/Stream.h"
#include "fd.h"

void
fd_open(const int fd, unsigned int, const char *description)
{
    debugs(51, 3, "FD " << fd << ' ' << description);
}

void
fd_close(const int fd)
{
    debugs(51, 3, "FD " << fd);
}

void
commSetCloseOnExec(int)
{
    // This stub is needed because DebugFile sets this flag for the open
    // cache.log file descriptor. Helpers and such must use stdout/stderr
    // instead of opening a cache.log file. They should never reach this code.
    assert(false);
}

