/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_DISKIO_DISKTHREADS_COMMIO_H
#define SQUID_SRC_DISKIO_DISKTHREADS_COMMIO_H

#include "fatal.h"
#include "fde.h"
#include "globals.h"

class CommIO
{

public:
    static inline void NotifyIOCompleted();
    static void ResetNotifications();
    static void Initialize();
    static void NotifyIOClose();

private:
    static void NULLFDHandler(int, void *);
    static void FlushPipe();
    static bool Initialized;
    static bool DoneSignalled;
    static int DoneFD;
    static int DoneReadFD;
};

/* Inline code. TODO: make structured approach to inlining */
void
CommIO::NotifyIOCompleted()
{
    if (!Initialized) {
        fatalf("Disk Threads I/O pipes not initialized before first use.");
    }

    if (!DoneSignalled) {
        DoneSignalled = true;
        FD_WRITE_METHOD(DoneFD, "!", 1);
    }
};

#endif /* SQUID_SRC_DISKIO_DISKTHREADS_COMMIO_H */

