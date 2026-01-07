/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "fde.cc"
#include "tests/STUB.h"

#include "fde.h"
void fde::Init() STUB
void fde::setIo(READ_HANDLER *, WRITE_HANDLER *) STUB
void fde::useDefaultIo() STUB
void fde::useBufferedIo(READ_HANDLER *, WRITE_HANDLER *) STUB
void fde::DumpStats(StoreEntry *) STUB
char const *fde::remoteAddr() const STUB_RETVAL(nullptr)
void fde::dumpStats(StoreEntry &, int) const STUB
bool fde::readPending(int) const STUB_RETVAL(false)
fde* fde::Table = nullptr;
int fdNFree() STUB_RETVAL(-1)
