/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "fd.h"
#include "fde.h"

#define STUB_API "fd.cc"
#include "tests/STUB.h"

fde *fde::Table = nullptr;

int fdNFree(void) STUB_RETVAL(-1)
void fd_open(int, unsigned int, const char *) STUB
void fd_close(int) STUB
void fd_bytes(int, int, unsigned int) STUB
void fd_note(int, const char *) STUB
void fdAdjustReserved() STUB

