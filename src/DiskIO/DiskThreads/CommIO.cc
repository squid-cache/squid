/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Disk I/O pipe manager */

#include "squid.h"
#include "comm/Loops.h"
#include "DiskIO/DiskThreads/CommIO.h"
#include "fd.h"
#include "globals.h"
#include "win32.h"

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
    Comm::SetSelect(DoneReadFD, COMM_SELECT_READ, NULLFDHandler, nullptr, 0);
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
CommIO::NULLFDHandler(int fd, void *)
{
    FlushPipe();
    Comm::SetSelect(fd, COMM_SELECT_READ, NULLFDHandler, nullptr, 0);
}

void
CommIO::ResetNotifications()
{
    if (DoneSignalled) {
        FlushPipe();
        DoneSignalled = false;
    }
}

