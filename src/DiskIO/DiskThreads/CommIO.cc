/*
 * DEBUG: section 05    Disk I/O pipe manager
 * AUTHOR: Harvest Derived
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "comm/Loops.h"
#include "DiskIO/DiskThreads/CommIO.h"
#include "fd.h"
#include "globals.h"

void
CommIO::Initialize()
{
    if (CommIO::Initialized)
        return;

    /* Initialize done pipe signal */
    int DonePipe[2];
    if (pipe(DonePipe)) {}
    DoneFD = DonePipe[1];
    DoneReadFD = DonePipe[0];
    fd_open(DoneReadFD, FD_PIPE, "async-io completion event: main");
    fd_open(DoneFD, FD_PIPE, "async-io completion event: threads");
    commSetNonBlocking(DoneReadFD);
    commSetNonBlocking(DoneFD);
    Comm::SetSelect(DoneReadFD, COMM_SELECT_READ, NULLFDHandler, NULL, 0);
    Initialized = true;
}

void
CommIO::NotifyIOClose()
{
    /* Close done pipe signal */
    FlushPipe();
    close(DoneFD);
    close(DoneReadFD);
    fd_close(DoneFD);
    fd_close(DoneReadFD);
    Initialized = false;
}

bool CommIO::Initialized = false;
bool CommIO::DoneSignalled = false;
int CommIO::DoneFD = -1;
int CommIO::DoneReadFD = -1;

void
CommIO::FlushPipe()
{
    char buf[256];
    FD_READ_METHOD(DoneReadFD, buf, sizeof(buf));
}

void
CommIO::NULLFDHandler(int fd, void *data)
{
    FlushPipe();
    Comm::SetSelect(fd, COMM_SELECT_READ, NULLFDHandler, NULL, 0);
}

void
CommIO::ResetNotifications()
{
    if (DoneSignalled) {
        FlushPipe();
        DoneSignalled = false;
    }
}
