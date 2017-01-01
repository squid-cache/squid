/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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
RemovalPolicy * createRemovalPolicy(RemovalPolicySettings * settings) STUB_RETVAL(NULL)

#include "Store.h"
StoreIoStats store_io_stats;
bool StoreEntry::checkDeferRead(int fd) const STUB_RETVAL(false)
const char *StoreEntry::getMD5Text() const STUB_RETVAL(NULL)
StoreEntry::StoreEntry() STUB
StoreEntry::~StoreEntry() STUB
HttpReply const *StoreEntry::getReply() const STUB_RETVAL(NULL)
void StoreEntry::write(StoreIOBuffer) STUB
bool StoreEntry::isAccepting() const STUB_RETVAL(false)
size_t StoreEntry::bytesWanted(Range<size_t> const, bool) const STUB_RETVAL(0)
void StoreEntry::complete() STUB
store_client_t StoreEntry::storeClientType() const STUB_RETVAL(STORE_NON_CLIENT)
char const *StoreEntry::getSerialisedMetaData() STUB_RETVAL(NULL)
void StoreEntry::replaceHttpReply(HttpReply *, bool andStartWriting) STUB
bool StoreEntry::mayStartSwapOut() STUB_RETVAL(false)
void StoreEntry::trimMemory(const bool preserveSwappable) STUB
void StoreEntry::abort() STUB
void StoreEntry::makePublic(const KeyScope scope) STUB
void StoreEntry::makePrivate() STUB
void StoreEntry::setPublicKey(const KeyScope scope) STUB
void StoreEntry::setPrivateKey() STUB
void StoreEntry::expireNow() STUB
void StoreEntry::releaseRequest() STUB
void StoreEntry::negativeCache() STUB
void StoreEntry::cacheNegatively() STUB
void StoreEntry::purgeMem() STUB
void StoreEntry::swapOut() STUB
void StoreEntry::swapOutFileClose(int how) STUB
const char *StoreEntry::url() const STUB_RETVAL(NULL)
bool StoreEntry::checkCachable() STUB_RETVAL(false)
int StoreEntry::checkNegativeHit() const STUB_RETVAL(0)
int StoreEntry::locked() const STUB_RETVAL(0)
int StoreEntry::validToSend() const STUB_RETVAL(0)
bool StoreEntry::memoryCachable() STUB_RETVAL(false)
MemObject *StoreEntry::makeMemObject() STUB_RETVAL(NULL)
void StoreEntry::createMemObject(const char *, const char *, const HttpRequestMethod &aMethod) STUB
void StoreEntry::dump(int debug_lvl) const STUB
void StoreEntry::hashDelete() STUB
void StoreEntry::hashInsert(const cache_key *) STUB
void StoreEntry::registerAbort(STABH * cb, void *) STUB
void StoreEntry::reset() STUB
void StoreEntry::setMemStatus(mem_status_t) STUB
bool StoreEntry::timestampsSet() STUB_RETVAL(false)
void StoreEntry::unregisterAbort() STUB
void StoreEntry::destroyMemObject() STUB
int StoreEntry::checkTooSmall() STUB_RETVAL(0)
void StoreEntry::delayAwareRead(const Comm::ConnectionPointer&, char *buf, int len, AsyncCall::Pointer callback) STUB
void StoreEntry::setNoDelay (bool const) STUB
bool StoreEntry::modifiedSince(const time_t, const int) const STUB_RETVAL(false)
bool StoreEntry::hasIfMatchEtag(const HttpRequest &request) const STUB_RETVAL(false)
bool StoreEntry::hasIfNoneMatchEtag(const HttpRequest &request) const STUB_RETVAL(false)
Store::Disk &StoreEntry::disk() const STUB_RETREF(Store::Disk)
size_t StoreEntry::inUseCount() STUB_RETVAL(0)
void StoreEntry::getPublicByRequestMethod(StoreClient * aClient, HttpRequest * request, const HttpRequestMethod& method) STUB
void StoreEntry::getPublicByRequest(StoreClient * aClient, HttpRequest * request) STUB
void StoreEntry::getPublic(StoreClient * aClient, const char *uri, const HttpRequestMethod& method) STUB
void *StoreEntry::operator new(size_t byteCount)
{
    STUB
    return new StoreEntry();
}
void StoreEntry::operator delete(void *address) STUB
void StoreEntry::setReleaseFlag() STUB
//#if USE_SQUID_ESI
//ESIElement::Pointer StoreEntry::cachedESITree STUB_RETVAL(NULL)
//#endif
void StoreEntry::buffer() STUB
void StoreEntry::flush() STUB
int StoreEntry::unlock(const char *) STUB_RETVAL(0)
int64_t StoreEntry::objectLen() const STUB_RETVAL(0)
int64_t StoreEntry::contentLen() const STUB_RETVAL(0)
void StoreEntry::lock(const char *) STUB
void StoreEntry::touch() STUB
void StoreEntry::release() STUB
void StoreEntry::append(char const *, int) STUB
void StoreEntry::vappendf(const char *, va_list) STUB

NullStoreEntry *NullStoreEntry::getInstance() STUB_RETVAL(NULL)
const char *NullStoreEntry::getMD5Text() const STUB_RETVAL(NULL)
void NullStoreEntry::operator delete(void *address) STUB
// private virtual. Why is this linked from outside?
const char *NullStoreEntry::getSerialisedMetaData() STUB_RETVAL(NULL)

Store::Controller &Store::Root() STUB_RETREF(Store::Controller)
void Store::Init(Store::Controller *root) STUB
void Store::FreeMemory() STUB
void Store::Stats(StoreEntry * output) STUB
void Store::Maintain(void *unused) STUB
int Store::Controller::store_dirs_rebuilding = 0;
StoreSearch *Store::Controller::search() STUB_RETVAL(NULL)
void Store::Controller::maintain() STUB

std::ostream &operator <<(std::ostream &os, const StoreEntry &)
{
    STUB
    return os;
}

size_t storeEntryInUse() STUB_RETVAL(0)
void storeEntryReplaceObject(StoreEntry *, HttpReply *) STUB
StoreEntry *storeGetPublic(const char *uri, const HttpRequestMethod& method) STUB_RETVAL(NULL)
StoreEntry *storeGetPublicByRequest(HttpRequest * request, const KeyScope scope) STUB_RETVAL(NULL)
StoreEntry *storeGetPublicByRequestMethod(HttpRequest * request, const HttpRequestMethod& method, const KeyScope scope) STUB_RETVAL(NULL)
StoreEntry *storeCreateEntry(const char *, const char *, const RequestFlags &, const HttpRequestMethod&) STUB_RETVAL(NULL)
StoreEntry *storeCreatePureEntry(const char *storeId, const char *logUrl, const RequestFlags &, const HttpRequestMethod&) STUB_RETVAL(NULL)
void storeConfigure(void) STUB
int expiresMoreThan(time_t, time_t) STUB_RETVAL(0)
void storeAppendPrintf(StoreEntry *, const char *,...) STUB
void storeAppendVPrintf(StoreEntry *, const char *, va_list ap) STUB
int storeTooManyDiskFilesOpen(void) STUB_RETVAL(0)
void storeHeapPositionUpdate(StoreEntry *, SwapDir *) STUB
void storeSwapFileNumberSet(StoreEntry * e, sfileno filn) STUB
void storeFsInit(void) STUB
void storeFsDone(void) STUB
void storeReplAdd(const char *, REMOVALPOLICYCREATE *) STUB
void destroyStoreEntry(void *) STUB
void storeGetMemSpace(int size) STUB

