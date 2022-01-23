/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "comm/Connection.h"
#include "HttpReply.h"
#include "MemObject.h"
#if USE_DELAY_POOLS
#include "DelayPools.h"
#endif

#define STUB_API "MemObject.cc"
#include "tests/STUB.h"

RemovalPolicy * mem_policy = NULL;

int64_t
MemObject::endOffset() const
{
    // XXX: required by testStore
    return data_hdr.endOffset();
}

void MemObject::trimSwappable() STUB
void MemObject::trimUnSwappable() STUB
int64_t MemObject::policyLowestOffsetToKeep(bool swap) const STUB_RETVAL(-1)
MemObject::MemObject() {
    ping_reply_callback = nullptr;
    memset(&start_ping, 0, sizeof(start_ping));
} // NOP instead of elided due to Store

const char *MemObject::storeId() const STUB_RETVAL(NULL)
const char *MemObject::logUri() const STUB_RETVAL(NULL)
void MemObject::setUris(char const *aStoreId, char const *aLogUri, const HttpRequestMethod &aMethod) STUB
void MemObject::reset() STUB
void MemObject::delayRead(DeferredRead const &aRead) STUB
bool MemObject::readAheadPolicyCanRead() const STUB_RETVAL(false)
void MemObject::setNoDelay(bool const newValue) STUB
MemObject::~MemObject() STUB
int MemObject::mostBytesWanted(int max, bool ignoreDelayPools) const STUB_RETVAL(-1)
#if USE_DELAY_POOLS
DelayId MemObject::mostBytesAllowed() const STUB_RETVAL(DelayId())
#endif
void MemObject::write(const StoreIOBuffer &writeBuffer) STUB
int64_t MemObject::lowestMemReaderOffset() const STUB_RETVAL(0)
void MemObject::kickReads() STUB
int64_t MemObject::objectBytesOnDisk() const STUB_RETVAL(0)
bool MemObject::isContiguous() const STUB_RETVAL(false)
int64_t MemObject::expectedReplySize() const STUB_RETVAL(0)
void MemObject::markEndOfReplyHeaders() STUB
size_t MemObject::inUseCount() STUB_RETVAL(0)
int64_t MemObject::availableForSwapOut() const STUB_RETVAL(0)

