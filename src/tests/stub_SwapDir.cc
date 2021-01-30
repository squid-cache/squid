/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "store/Disk.h"

#define STUB_API "store/Disk.cc"
#include "tests/STUB.h"

// SwapDir::SwapDir(char const *) STUB
// SwapDir::~SwapDir() STUB
void SwapDir::create() STUB
void SwapDir::dump(StoreEntry &) const STUB
bool SwapDir::doubleCheck(StoreEntry &) STUB_RETVAL(false)
void SwapDir::getStats(StoreInfoStats &) const STUB
void SwapDir::stat(StoreEntry &) const STUB
void SwapDir::statfs(StoreEntry &)const STUB
void SwapDir::maintain() STUB
uint64_t SwapDir::minSize() const STUB_RETVAL(0)
int64_t SwapDir::minObjectSize() const STUB_RETVAL(0)
int64_t SwapDir::maxObjectSize() const STUB_RETVAL(0)
void SwapDir::maxObjectSize(int64_t) STUB
void SwapDir::reference(StoreEntry &) STUB
bool SwapDir::dereference(StoreEntry &) STUB_RETVAL(false)
bool SwapDir::canStore(const StoreEntry &, int64_t, int &) const STUB_RETVAL(false)
bool SwapDir::canLog(StoreEntry const &)const STUB_RETVAL(false)
void SwapDir::openLog() STUB
void SwapDir::closeLog() STUB
int SwapDir::writeCleanStart() STUB_RETVAL(0)
void SwapDir::writeCleanDone() STUB
void SwapDir::logEntry(const StoreEntry &, int) const STUB
char const * SwapDir::type() const STUB_RETVAL("stub")
bool SwapDir::active() const STUB_RETVAL(false)
bool SwapDir::needsDiskStrand() const STUB_RETVAL(false)
ConfigOption * SwapDir::getOptionTree() const STUB_RETVAL(NULL)
void SwapDir::parseOptions(int) STUB
void SwapDir::dumpOptions(StoreEntry *) const STUB
bool SwapDir::optionReadOnlyParse(char const *, const char *, int) STUB_RETVAL(false)
void SwapDir::optionReadOnlyDump(StoreEntry *) const STUB
bool SwapDir::optionObjectSizeParse(char const *, const char *, int) STUB_RETVAL(false)
void SwapDir::optionObjectSizeDump(StoreEntry *) const STUB
StoreEntry * SwapDir::get(const cache_key *) STUB_RETVAL(NULL)

