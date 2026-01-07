/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "fd.cc"
#include "tests/STUB.h"

#include "fd.h"
void fd_close(int) STUB
void fd_open(int, unsigned int, const char *) STUB
void fd_note(int, const char *) STUB
void fd_bytes(int, int, IoDirection) STUB
void fdDumpOpen() STUB
int fdUsageHigh() STUB
void fdAdjustReserved() STUB
int default_read_method(int, char *, int) STUB_RETVAL(0)
int default_write_method(int, const char *, int) STUB_RETVAL(0)

// XXX: global. keep in sync with fd.cc
const char *fdTypeStr[] = {
    "None",
    "Log",
    "File",
    "Socket",
    "Pipe",
    "MsgHdr",
    "Unknown"
};
