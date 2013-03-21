#include "squid.h"
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
MemObject::MemObject(char const *, char const *) :
        url(NULL),
        inmem_lo(0),
        nclients(0),
        request(NULL),
        ping_reply_callback(NULL),
        ircb_data(NULL),
        log_url(NULL),
        id(0),
        object_sz(-1),
        swap_hdr_sz(0),
        vary_headers(NULL),
        _reply(NULL)
{
    memset(&clients, 0, sizeof(clients));
    memset(&start_ping, 0, sizeof(start_ping));
    memset(&abort, 0, sizeof(abort));
} // NOP instead of elided due to Store

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
int MemObject::mostBytesWanted(int max, bool ignoreDelayPools) const STUB_RETVAL(-1)
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
int64_t MemObject::availableForSwapOut() const STUB_RETVAL(0)
