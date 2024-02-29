/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
#include "pconn.h"

#define STUB_API "pconn.cc"
#include "tests/STUB.h"

IdleConnList::IdleConnList(const char *, PconnPool *) STUB
IdleConnList::~IdleConnList() STUB
void IdleConnList::push(const Comm::ConnectionPointer &) STUB
Comm::ConnectionPointer IdleConnList::findUseable(const Comm::ConnectionPointer &) STUB_RETVAL(Comm::ConnectionPointer())
void IdleConnList::clearHandlers(const Comm::ConnectionPointer &) STUB
void IdleConnList::endingShutdown() STUB
PconnPool::PconnPool(const char *, const CbcPointer<PeerPoolMgr>&) STUB
PconnPool::~PconnPool() STUB
void PconnPool::moduleInit() STUB
void PconnPool::push(const Comm::ConnectionPointer &, const char *) STUB
Comm::ConnectionPointer PconnPool::pop(const Comm::ConnectionPointer &, const char *, bool) STUB_RETVAL(Comm::ConnectionPointer())
void PconnPool::count(int) STUB
void PconnPool::noteUses(int) STUB
void PconnPool::dumpHist(StoreEntry *) const STUB
void PconnPool::dumpHash(StoreEntry *) const STUB
void PconnPool::unlinkList(IdleConnList *) STUB
PconnModule * PconnModule::GetInstance() STUB_RETVAL(nullptr)
void PconnModule::DumpWrapper(StoreEntry *) STUB
PconnModule::PconnModule() STUB
void PconnModule::registerWithCacheManager(void) STUB
void PconnModule::add(PconnPool *) STUB
void PconnModule::dump(StoreEntry *) STUB

