/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "RequestFlags.h"

#define STUB_API "store.cc"
#include "tests/STUB.h"

const char *storeStatusStr[] = { };
const char *pingStatusStr[] = { };
const char *memStatusStr[] = { };
const char *swapStatusStr[] = { };

#include "RemovalPolicy.h"
RemovalPolicy * createRemovalPolicy(RemovalPolicySettings *) STUB_RETVAL(nullptr)

#include "Store.h"
StoreIoStats store_io_stats;
bool StoreEntry::checkDeferRead(int) const STUB_RETVAL(false)
const char *StoreEntry::getMD5Text() const STUB_RETVAL(nullptr)
StoreEntry::StoreEntry() STUB
StoreEntry::~StoreEntry() STUB
void StoreEntry::write(StoreIOBuffer) STUB
bool StoreEntry::isAccepting() const STUB_RETVAL(false)
size_t StoreEntry::bytesWanted(Range<size_t> const, bool) const STUB_RETVAL(0)
void StoreEntry::complete() STUB
store_client_t StoreEntry::storeClientType() const STUB_RETVAL(STORE_NON_CLIENT)
char const *StoreEntry::getSerialisedMetaData(size_t &) const STUB_RETVAL(nullptr)
void StoreEntry::replaceHttpReply(const HttpReplyPointer &, bool) STUB
bool StoreEntry::mayStartSwapOut() STUB_RETVAL(false)
void StoreEntry::trimMemory(const bool) STUB
void StoreEntry::abort() STUB
bool StoreEntry::makePublic(const KeyScope) STUB
void StoreEntry::makePrivate(const bool) STUB
bool StoreEntry::setPublicKey(const KeyScope) STUB
void StoreEntry::setPrivateKey(const bool, const bool) STUB
void StoreEntry::expireNow() STUB
void StoreEntry::releaseRequest(const bool) STUB
void StoreEntry::negativeCache() STUB
bool StoreEntry::cacheNegatively() STUB
void StoreEntry::swapOut() STUB
void StoreEntry::swapOutFileClose(int) STUB
const char *StoreEntry::url() const STUB_RETVAL(nullptr)
bool StoreEntry::checkCachable() STUB_RETVAL(false)
int StoreEntry::checkNegativeHit() const STUB_RETVAL(0)
int StoreEntry::validToSend() const STUB_RETVAL(0)
bool StoreEntry::memoryCachable() STUB_RETVAL(false)
void StoreEntry::createMemObject() STUB
void StoreEntry::createMemObject(const char *, const char *, const HttpRequestMethod &) STUB
void StoreEntry::ensureMemObject(const char *, const char *, const HttpRequestMethod &) STUB
void StoreEntry::dump(int) const STUB
void StoreEntry::hashDelete() STUB
void StoreEntry::hashInsert(const cache_key *) STUB
void StoreEntry::registerAbortCallback(const AsyncCall::Pointer &) STUB
void StoreEntry::reset() STUB
void StoreEntry::setMemStatus(mem_status_t) STUB
bool StoreEntry::timestampsSet() STUB_RETVAL(false)
void StoreEntry::unregisterAbortCallback(const char *) STUB
void StoreEntry::destroyMemObject() STUB
int StoreEntry::checkTooSmall() STUB_RETVAL(0)
void StoreEntry::setNoDelay (bool const) STUB
bool StoreEntry::modifiedSince(const time_t, const int) const STUB_RETVAL(false)
bool StoreEntry::hasIfMatchEtag(const HttpRequest &) const STUB_RETVAL(false)
bool StoreEntry::hasIfNoneMatchEtag(const HttpRequest &) const STUB_RETVAL(false)
Store::Disk &StoreEntry::disk() const STUB_RETREF(Store::Disk)
size_t StoreEntry::inUseCount() STUB_RETVAL(0)
void *StoreEntry::operator new(size_t)
{
    STUB
    return new StoreEntry();
}
void StoreEntry::operator delete(void *) STUB
//#if USE_SQUID_ESI
//ESIElement::Pointer StoreEntry::cachedESITree STUB_RETVAL(nullptr)
//#endif
void StoreEntry::buffer() STUB
void StoreEntry::flush() STUB
int StoreEntry::unlock(const char *) STUB_RETVAL(0)
void StoreEntry::lock(const char *) STUB
void StoreEntry::touch() STUB
void StoreEntry::release(const bool) STUB
void StoreEntry::append(char const *, int) STUB
void StoreEntry::vappendf(const char *, va_list) STUB
void StoreEntry::setCollapsingRequirement(const bool) STUB

void Store::Maintain(void *) STUB

std::ostream &operator <<(std::ostream &os, const StoreEntry &)
{
    STUB
    return os;
}

size_t storeEntryInUse() STUB_RETVAL(0)
void storeEntryReplaceObject(StoreEntry *, HttpReply *) STUB
StoreEntry *storeGetPublic(const char *, const HttpRequestMethod&) STUB_RETVAL(nullptr)
StoreEntry *storeGetPublicByRequest(HttpRequest *, const KeyScope) STUB_RETVAL(nullptr)
StoreEntry *storeGetPublicByRequestMethod(HttpRequest *, const HttpRequestMethod&, const KeyScope) STUB_RETVAL(nullptr)
StoreEntry *storeCreateEntry(const char *, const char *, const RequestFlags &, const HttpRequestMethod&) STUB_RETVAL(nullptr)
StoreEntry *storeCreatePureEntry(const char *, const char *, const HttpRequestMethod&) STUB_RETVAL(nullptr)
void storeConfigure(void) STUB
int expiresMoreThan(time_t, time_t) STUB_RETVAL(0)
void storeAppendPrintf(StoreEntry *, const char *,...) STUB
void storeAppendVPrintf(StoreEntry *, const char *, va_list) STUB
int storeTooManyDiskFilesOpen(void) STUB_RETVAL(0)
void storeHeapPositionUpdate(StoreEntry *, SwapDir *) STUB
void storeSwapFileNumberSet(StoreEntry *, sfileno) STUB
void storeFsInit(void) STUB
void storeFsDone(void) STUB
void storeReplAdd(const char *, REMOVALPOLICYCREATE *) STUB
void destroyStoreEntry(void *) STUB
void storeGetMemSpace(int) STUB

