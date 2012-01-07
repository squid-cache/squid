#include "config.h"
#include "comm/Connection.h"
#include "MemObject.h"
#include "HttpReply.h"
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
MemObject::MemObject(char const *, char const *) {} // NOP due to Store
HttpReply const * MemObject::getReply() const
{
    // XXX: required by testStore
    return NULL;
}
void MemObject::reset() STUB
void MemObject::delayRead(DeferredRead const &aRead) STUB
bool MemObject::readAheadPolicyCanRead() const STUB_RETVAL(false)
void MemObject::setNoDelay(bool const newValue) STUB
MemObject::~MemObject() STUB
int MemObject::mostBytesWanted(int max) const STUB_RETVAL(-1)
#if USE_DELAY_POOLS
DelayId MemObject::mostBytesAllowed() const STUB_RETVAL(DelayId())
#endif
void MemObject::unlinkRequest() STUB
void MemObject::write(StoreIOBuffer writeBuffer, STMCB *callback, void *callbackData) STUB
void MemObject::replaceHttpReply(HttpReply *newrep) STUB
int64_t MemObject::lowestMemReaderOffset() const STUB_RETVAL(0)
void MemObject::kickReads() STUB
int64_t MemObject::objectBytesOnDisk() const STUB_RETVAL(0)
bool MemObject::isContiguous() const STUB_RETVAL(false)
int64_t MemObject::expectedReplySize() const STUB_RETVAL(0)
void MemObject::resetUrls(char const*, char const*) STUB
void MemObject::markEndOfReplyHeaders() STUB
size_t MemObject::inUseCount() STUB_RETVAL(0)
