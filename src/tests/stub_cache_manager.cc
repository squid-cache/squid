/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "CacheManager.h"
#include "debug/Stream.h"
#include "mgr/Registration.h"

#define STUB_API "cache_manager.cc"
#include "tests/STUB.h"

Mgr::Action::Pointer CacheManager::createNamedAction(char const*) STUB_RETVAL(nullptr)
void CacheManager::start(const Comm::ConnectionPointer &, HttpRequest *, StoreEntry *, const AccessLogEntryPointer &) STUB
static CacheManager* instance = nullptr;
CacheManager* CacheManager::GetInstance() STUB_RETVAL(instance)
void Mgr::RegisterAction(char const *, char const *, OBJH *, Protected, Atomic, Format) {}
void Mgr::RegisterAction(char const *, char const *, ClassActionCreationHandler *, Protected, Atomic, Format) {}

Mgr::Action::Pointer CacheManager::createRequestedAction(const Mgr::ActionParams &) STUB_RETVAL(nullptr)
void CacheManager::PutCommonResponseHeaders(HttpReply &, const char *) STUB

