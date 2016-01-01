/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 19    Store Memory Primitives */

#include "squid.h"
#include "comm/Connection.h"
#include "Generic.h"
#include "globals.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "MemObject.h"
#include "profiler/Profiler.h"
#include "SquidConfig.h"
#include "Store.h"
#include "StoreClient.h"

#if USE_DELAY_POOLS
#include "DelayPools.h"
#endif

/* TODO: make this global or private */
#if URL_CHECKSUM_DEBUG
static unsigned int url_checksum(const char *url);
unsigned int
url_checksum(const char *url)
{
    unsigned int ck;
    SquidMD5_CTX M;
    static unsigned char digest[16];
    SquidMD5Init(&M);
    SquidMD5Update(&M, (unsigned char *) url, strlen(url));
    SquidMD5Final(digest, &M);
    memcpy(&ck, digest, sizeof(ck));
    return ck;
}

#endif

RemovalPolicy * mem_policy = NULL;

size_t
MemObject::inUseCount()
{
    return Pool().inUseCount();
}

const char *
MemObject::storeId() const
{
    if (!storeId_.size()) {
        debugs(20, DBG_IMPORTANT, "Bug: Missing MemObject::storeId value");
        dump();
        storeId_ = "[unknown_URI]";
    }
    return storeId_.termedBuf();
}

const char *
MemObject::logUri() const
{
    return logUri_.size() ? logUri_.termedBuf() : storeId();
}

bool
MemObject::hasUris() const
{
    return storeId_.size();
}

void
MemObject::setUris(char const *aStoreId, char const *aLogUri, const HttpRequestMethod &aMethod)
{
    storeId_ = aStoreId;

    // fast pointer comparison for a common storeCreateEntry(url,url,...) case
    if (!aLogUri || aLogUri == aStoreId)
        logUri_.clean(); // use storeId_ by default to minimize copying
    else
        logUri_ = aLogUri;

    method = aMethod;

#if URL_CHECKSUM_DEBUG
    chksum = url_checksum(urlXXX());
#endif
}

MemObject::MemObject(): smpCollapsed(false)
{
    debugs(20, 3, HERE << "new MemObject " << this);
    _reply = new HttpReply;
    HTTPMSGLOCK(_reply);

    object_sz = -1;

    /* XXX account log_url */

    swapout.decision = SwapOut::swNeedsCheck;
}

MemObject::~MemObject()
{
    debugs(20, 3, HERE << "del MemObject " << this);
    const Ctx ctx = ctx_enter(hasUris() ? urlXXX() : "[unknown_ctx]");

#if URL_CHECKSUM_DEBUG
    checkUrlChecksum();
#endif

    if (!shutting_down) { // Store::Root() is FATALly missing during shutdown
        assert(xitTable.index < 0);
        assert(memCache.index < 0);
        assert(swapout.sio == NULL);
    }

    data_hdr.freeContent();

#if 0
    /*
     * There is no way to abort FD-less clients, so they might
     * still have mem->clients set.
     */
    assert(clients.head == NULL);

#endif

    HTTPMSGUNLOCK(_reply);

    HTTPMSGUNLOCK(request);

    ctx_exit(ctx);              /* must exit before we free mem->url */

    safe_free(vary_headers);
}

void
MemObject::unlinkRequest()
{
    HTTPMSGUNLOCK(request);
}

void
MemObject::write(const StoreIOBuffer &writeBuffer)
{
    PROF_start(MemObject_write);
    debugs(19, 6, "memWrite: offset " << writeBuffer.offset << " len " << writeBuffer.length);

    /* We don't separate out mime headers yet, so ensure that the first
     * write is at offset 0 - where they start
     */
    assert (data_hdr.endOffset() || writeBuffer.offset == 0);

    assert (data_hdr.write (writeBuffer));
    PROF_stop(MemObject_write);
}

void
MemObject::dump() const
{
    data_hdr.dump();
#if 0
    /* do we want this one? */
    debugs(20, DBG_IMPORTANT, "MemObject->data.origin_offset: " << (data_hdr.head ? data_hdr.head->nodeBuffer.offset : 0));
#endif

    debugs(20, DBG_IMPORTANT, "MemObject->start_ping: " << start_ping.tv_sec  << "."<< std::setfill('0') << std::setw(6) << start_ping.tv_usec);
    debugs(20, DBG_IMPORTANT, "MemObject->inmem_hi: " << data_hdr.endOffset());
    debugs(20, DBG_IMPORTANT, "MemObject->inmem_lo: " << inmem_lo);
    debugs(20, DBG_IMPORTANT, "MemObject->nclients: " << nclients);
    debugs(20, DBG_IMPORTANT, "MemObject->reply: " << _reply);
    debugs(20, DBG_IMPORTANT, "MemObject->request: " << request);
    debugs(20, DBG_IMPORTANT, "MemObject->logUri: " << logUri_);
    debugs(20, DBG_IMPORTANT, "MemObject->storeId: " << storeId_);
}

HttpReply const *
MemObject::getReply() const
{
    return _reply;
}

void
MemObject::replaceHttpReply(HttpReply *newrep)
{
    HTTPMSGUNLOCK(_reply);
    _reply = newrep;
    HTTPMSGLOCK(_reply);
}

struct LowestMemReader : public unary_function<store_client, void> {
    LowestMemReader(int64_t seed):current(seed) {}

    void operator() (store_client const &x) {
        if (x.memReaderHasLowerOffset(current))
            current = x.copyInto.offset;
    }

    int64_t current;
};

struct StoreClientStats : public unary_function<store_client, void> {
    StoreClientStats(MemBuf *anEntry):where(anEntry),index(0) {}

    void operator()(store_client const &x) {
        x.dumpStats(where, index);
        ++index;
    }

    MemBuf *where;
    size_t index;
};

void
MemObject::stat(MemBuf * mb) const
{
    mb->Printf("\t" SQUIDSBUFPH " %s\n", SQUIDSBUFPRINT(method.image()), logUri());
    if (vary_headers)
        mb->Printf("\tvary_headers: %s\n", vary_headers);
    mb->Printf("\tinmem_lo: %" PRId64 "\n", inmem_lo);
    mb->Printf("\tinmem_hi: %" PRId64 "\n", data_hdr.endOffset());
    mb->Printf("\tswapout: %" PRId64 " bytes queued\n",
               swapout.queue_offset);

    if (swapout.sio.getRaw())
        mb->Printf("\tswapout: %" PRId64 " bytes written\n",
                   (int64_t) swapout.sio->offset());

    if (xitTable.index >= 0)
        mb->Printf("\ttransient index: %d state: %d\n",
                   xitTable.index, xitTable.io);
    if (memCache.index >= 0)
        mb->Printf("\tmem-cache index: %d state: %d offset: %" PRId64 "\n",
                   memCache.index, memCache.io, memCache.offset);
    if (object_sz >= 0)
        mb->Printf("\tobject_sz: %" PRId64 "\n", object_sz);
    if (smpCollapsed)
        mb->Printf("\tsmp-collapsed\n");

    StoreClientStats statsVisitor(mb);

    for_each<StoreClientStats>(clients, statsVisitor);
}

int64_t
MemObject::endOffset () const
{
    return data_hdr.endOffset();
}

void
MemObject::markEndOfReplyHeaders()
{
    const int hdr_sz = endOffset();
    assert(hdr_sz >= 0);
    assert(_reply);
    _reply->hdr_sz = hdr_sz;
}

int64_t
MemObject::size() const
{
    if (object_sz < 0)
        return endOffset();

    return object_sz;
}

int64_t
MemObject::expectedReplySize() const
{
    debugs(20, 7, HERE << "object_sz: " << object_sz);
    if (object_sz >= 0) // complete() has been called; we know the exact answer
        return object_sz;

    if (_reply) {
        const int64_t clen = _reply->bodySize(method);
        debugs(20, 7, HERE << "clen: " << clen);
        if (clen >= 0 && _reply->hdr_sz > 0) // yuck: HttpMsg sets hdr_sz to 0
            return clen + _reply->hdr_sz;
    }

    return -1; // not enough information to predict
}

void
MemObject::reset()
{
    assert(swapout.sio == NULL);
    data_hdr.freeContent();
    inmem_lo = 0;
    /* Should we check for clients? */
}

int64_t
MemObject::lowestMemReaderOffset() const
{
    LowestMemReader lowest (endOffset() + 1);

    for_each <LowestMemReader>(clients, lowest);

    return lowest.current;
}

/* XXX: This is wrong. It breaks *badly* on range combining */
bool
MemObject::readAheadPolicyCanRead() const
{
    const bool canRead = endOffset() - getReply()->hdr_sz <
                         lowestMemReaderOffset() + Config.readAheadGap;

    if (!canRead) {
        debugs(19, 9, "no: " << endOffset() << '-' << getReply()->hdr_sz <<
               " < " << lowestMemReaderOffset() << '+' << Config.readAheadGap);
    }

    return canRead;
}

void
MemObject::addClient(store_client *aClient)
{
    ++nclients;
    dlinkAdd(aClient, &aClient->node, &clients);
}

#if URL_CHECKSUM_DEBUG
void
MemObject::checkUrlChecksum () const
{
    assert(chksum == url_checksum(urlXXX()));
}

#endif

/*
 * How much of the object data is on the disk?
 */
int64_t
MemObject::objectBytesOnDisk() const
{
    /*
     * NOTE: storeOffset() represents the disk file size,
     * not the amount of object data on disk.
     *
     * If we don't have at least 'swap_hdr_sz' bytes
     * then none of the object data is on disk.
     *
     * This should still be safe if swap_hdr_sz == 0,
     * meaning we haven't even opened the swapout file
     * yet.
     */

    if (swapout.sio.getRaw() == NULL)
        return 0;

    int64_t nwritten = swapout.sio->offset();

    if (nwritten <= (int64_t)swap_hdr_sz)
        return 0;

    return (nwritten - swap_hdr_sz);
}

int64_t
MemObject::policyLowestOffsetToKeep(bool swap) const
{
    /*
     * Careful.  lowest_offset can be greater than endOffset(), such
     * as in the case of a range request.
     */
    int64_t lowest_offset = lowestMemReaderOffset();

    if (endOffset() < lowest_offset ||
            endOffset() - inmem_lo > (int64_t)Config.Store.maxInMemObjSize ||
            (swap && !Config.onoff.memory_cache_first))
        return lowest_offset;

    return inmem_lo;
}

void
MemObject::trimSwappable()
{
    int64_t new_mem_lo = policyLowestOffsetToKeep(1);
    /*
     * We should only free up to what we know has been written
     * to disk, not what has been queued for writing.  Otherwise
     * there will be a chunk of the data which is not in memory
     * and is not yet on disk.
     * The -1 makes sure the page isn't freed until storeSwapOut has
     * walked to the next page.
     */
    int64_t on_disk;

    if ((on_disk = objectBytesOnDisk()) - 1 < new_mem_lo)
        new_mem_lo = on_disk - 1;

    if (new_mem_lo == -1)
        new_mem_lo = 0; /* the above might become -1 */

    data_hdr.freeDataUpto(new_mem_lo);

    inmem_lo = new_mem_lo;
}

void
MemObject::trimUnSwappable()
{
    if (const int64_t new_mem_lo = policyLowestOffsetToKeep(false)) {
        assert (new_mem_lo > 0);
        data_hdr.freeDataUpto(new_mem_lo);
        inmem_lo = new_mem_lo;
    } // else we should not trim anything at this time
}

bool
MemObject::isContiguous() const
{
    bool result = data_hdr.hasContigousContentRange (Range<int64_t>(inmem_lo, endOffset()));
    /* XXX : make this higher level */
    debugs (19, result ? 4 :3, "MemObject::isContiguous: Returning " << (result ? "true" : "false"));
    return result;
}

int
MemObject::mostBytesWanted(int max, bool ignoreDelayPools) const
{
#if USE_DELAY_POOLS
    if (!ignoreDelayPools) {
        /* identify delay id with largest allowance */
        DelayId largestAllowance = mostBytesAllowed ();
        return largestAllowance.bytesWanted(0, max);
    }
#endif

    return max;
}

void
MemObject::setNoDelay(bool const newValue)
{
#if USE_DELAY_POOLS

    for (dlink_node *node = clients.head; node; node = node->next) {
        store_client *sc = (store_client *) node->data;
        sc->delayId.setNoDelay(newValue);
    }

#endif
}

void
MemObject::delayRead(DeferredRead const &aRead)
{
    deferredReads.delayRead(aRead);
}

void
MemObject::kickReads()
{
    deferredReads.kickReads(-1);
}

#if USE_DELAY_POOLS
DelayId
MemObject::mostBytesAllowed() const
{
    int j;
    int jmax = -1;
    DelayId result;

    for (dlink_node *node = clients.head; node; node = node->next) {
        store_client *sc = (store_client *) node->data;
#if 0
        /* This test is invalid because the client may be writing data
         * and thus will want data immediately.
         * If we include the test, there is a race condition when too much
         * data is read - if all sc's are writing when a read is scheduled.
         * XXX: fixme.
         */

        if (!sc->callbackPending())
            /* not waiting for more data */
            continue;

#endif

        j = sc->delayId.bytesWanted(0, sc->copyInto.length);

        if (j > jmax) {
            jmax = j;
            result = sc->delayId;
        }
    }

    return result;
}

#endif

int64_t
MemObject::availableForSwapOut() const
{
    return endOffset() - swapout.queue_offset;
}

