/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
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

