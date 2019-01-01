/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "CacheManager.h"
#include "Debug.h"
#include "mgr/Registration.h"

#define STUB_API "cache_manager.cc"
#include "tests/STUB.h"

Mgr::Action::Pointer CacheManager::createNamedAction(char const* action) STUB_RETVAL(NULL)
void CacheManager::Start(const Comm::ConnectionPointer &conn, HttpRequest * request, StoreEntry * entry)
{
    std::cerr << HERE << "\n";
    STUB
}
static CacheManager* instance = nullptr;
CacheManager* CacheManager::GetInstance() STUB_RETVAL(instance)
void Mgr::RegisterAction(char const*, char const*, OBJH, int, int) {}
void Mgr::RegisterAction(char const *, char const *, Mgr::ClassActionCreationHandler *, int, int) {}

Mgr::Action::Pointer CacheManager::createRequestedAction(const Mgr::ActionParams &) STUB_RETVAL(NULL)

