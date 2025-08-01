/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_DISKIO_DISKTHREADS

#define STUB_API "diskio/DiskThreads/CommIO.cc"
#include "tests/STUB.h"

#include "diskio/DiskThreads/CommIO.h"
bool CommIO::Initialised = false;
bool CommIO::DoneSignalled = false;
int CommIO::DoneFD = -1;
int CommIO::DoneReadFD = -1;
void CommIO::ResetNotifications() STUB
void CommIO::Initialise() STUB
void CommIO::NotifyIOClose() STUB
void CommIO::NULLFDHandler(int, void *) STUB
void CommIO::FlushPipe() STUB

#endif /* USE_DISKIO_DISKTHREADS */
