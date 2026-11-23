/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * STUB file for the pconn.cc API
 */
#include "squid.h"
#include "comm/Connection.h"

#define STUB_API "pconn.cc"
#include "tests/STUB.h"

#include "pconn.h"
PconnPool::PconnPool(const char *, const CbcPointer<PeerPoolMgr>&) STUB
PconnPool::~PconnPool() STUB
void PconnPool::moduleInit() STUB
void PconnPool::push(const Comm::ConnectionPointer &, const char *) STUB
Comm::ConnectionPointer PconnPool::pop(const Comm::ConnectionPointer &, const char *, bool) STUB_RETVAL(Comm::ConnectionPointer())
void PconnPool::count(int) STUB
void PconnPool::noteUses(int) STUB
void PconnPool::dump(std::ostream&) const STUB
void PconnPool::unlinkList(Comm::IdleConnList *) STUB
PconnModule * PconnModule::GetInstance() STUB_RETVAL(nullptr)
void PconnModule::DumpWrapper(StoreEntry *) STUB
PconnModule::PconnModule() STUB
void PconnModule::registerWithCacheManager(void) STUB
void PconnModule::add(PconnPool *) STUB
void PconnModule::dump(std::ostream &) STUB

