
/*
 * $Id$
 *
 * DEBUG: section 19    Store Memory Primitives
 * AUTHOR: Robert Collins
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "MemObject.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "Store.h"
#include "StoreClient.h"
#include "Generic.h"
#if DELAY_POOLS
#include "DelayPools.h"
#endif
#include "MemBuf.h"

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
    xmemcpy(&ck, digest, sizeof(ck));
    return ck;
}

#endif

RemovalPolicy * mem_policy = NULL;

size_t
MemObject::inUseCount()
{
    return Pool().inUseCount();
}

MemObject::MemObject(char const *aUrl, char const *aLog_url)
{
    debugs(20, 3, HERE << "new MemObject " << this);
    HttpReply *rep = new HttpReply;

    _reply  = HTTPMSGLOCK(rep);
    url = xstrdup(aUrl);

#if URL_CHECKSUM_DEBUG

    chksum = url_checksum(url);

#endif

    log_url = xstrdup(aLog_url);

    object_sz = -1;

    /* XXX account log_url */
}

MemObject::~MemObject()
{
    debugs(20, 3, HERE << "del MemObject " << this);
    const Ctx ctx = ctx_enter(url);
#if URL_CHECKSUM_DEBUG

    assert(chksum == url_checksum(url));
#endif

    if (!shutting_down)
        assert(swapout.sio == NULL);

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

    safe_free(url);

    safe_free(log_url);    /* XXX account log_url */

    safe_free(vary_headers);
}

void
MemObject::unlinkRequest()
{
    HTTPMSGUNLOCK(request);
}

void
MemObject::write ( StoreIOBuffer writeBuffer, STMCB *callback, void *callbackData)
{
    PROF_start(MemObject_write);
    debugs(19, 6, "memWrite: offset " << writeBuffer.offset << " len " << writeBuffer.length);

    /* the offset is into the content, not the headers */
    writeBuffer.offset += (_reply ? _reply->hdr_sz : 0);

    /* We don't separate out mime headers yet, so ensure that the first
     * write is at offset 0 - where they start
     */
    assert (data_hdr.endOffset() || writeBuffer.offset == 0);

    assert (data_hdr.write (writeBuffer));
    callback (callbackData, writeBuffer);
    PROF_stop(MemObject_write);
}

void
MemObject::dump() const
{
    data_hdr.dump();
#if 0
    /* do we want this one? */
    debugs(20, 1, "MemObject->data.origin_offset: " << (data_hdr.head ? data_hdr.head->nodeBuffer.offset : 0));
#endif

    debugs(20, 1, "MemObject->start_ping: " << start_ping.tv_sec  << "."<< std::setfill('0') << std::setw(6) << start_ping.tv_usec);
    debugs(20, 1, "MemObject->inmem_hi: " << data_hdr.endOffset());
    debugs(20, 1, "MemObject->inmem_lo: " << inmem_lo);
    debugs(20, 1, "MemObject->nclients: " << nclients);
    debugs(20, 1, "MemObject->reply: " << _reply);
    debugs(20, 1, "MemObject->request: " << request);
    debugs(20, 1, "MemObject->log_url: " << log_url << " " << checkNullString(log_url));
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
    _reply = HTTPMSGLOCK(newrep);
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
        x.dumpStats(where, index++);
    }

    MemBuf *where;
    size_t index;
};

void
MemObject::stat(MemBuf * mb) const
{
    mb->Printf("\t%s %s\n",
               RequestMethodStr(method), log_url);
    if (vary_headers)
        mb->Printf("\tvary_headers: %s\n", vary_headers);
    mb->Printf("\tinmem_lo: %"PRId64"\n", inmem_lo);
    mb->Printf("\tinmem_hi: %"PRId64"\n", data_hdr.endOffset());
    mb->Printf("\tswapout: %"PRId64" bytes queued\n",
               swapout.queue_offset);

    if (swapout.sio.getRaw())
        mb->Printf("\tswapout: %"PRId64" bytes written\n",
                   (int64_t) swapout.sio->offset());

    StoreClientStats statsVisitor(mb);

    for_each<StoreClientStats>(clients, statsVisitor);
}

int64_t
MemObject::endOffset () const
{
    return data_hdr.endOffset();
}

int64_t
MemObject::size() const
{
    if (object_sz < 0)
        return endOffset();

    return object_sz;
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
    return endOffset() - getReply()->hdr_sz < lowestMemReaderOffset() + Config.readAheadGap;
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
    assert(chksum == url_checksum(url));
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
MemObject::policyLowestOffsetToKeep() const
{
    /*
     * Careful.  lowest_offset can be greater than endOffset(), such
     * as in the case of a range request.
     */
    int64_t lowest_offset = lowestMemReaderOffset();

    if (endOffset() < lowest_offset ||
            endOffset() - inmem_lo > (int64_t)Config.Store.maxInMemObjSize)
        return lowest_offset;

    return inmem_lo;
}

void
MemObject::trimSwappable()
{
    int64_t new_mem_lo = policyLowestOffsetToKeep();
    /*
     * We should only free up to what we know has been written
     * to disk, not what has been queued for writing.  Otherwise
     * there will be a chunk of the data which is not in memory
     * and is not yet on disk.
     * The -1 makes sure the page isn't freed until storeSwapOut has
     * walked to the next page. (mem->swapout.memnode)
     */
    int64_t on_disk;

    if ((on_disk = objectBytesOnDisk()) - 1 < new_mem_lo)
        new_mem_lo = on_disk - 1;

    if (new_mem_lo == -1)
        new_mem_lo = 0;	/* the above might become -1 */

    data_hdr.freeDataUpto(new_mem_lo);

    inmem_lo = new_mem_lo;
}

void
MemObject::trimUnSwappable()
{
    int64_t new_mem_lo = policyLowestOffsetToKeep();
    assert (new_mem_lo > 0);

    data_hdr.freeDataUpto(new_mem_lo);
    inmem_lo = new_mem_lo;
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
MemObject::mostBytesWanted(int max) const
{
#if DELAY_POOLS
    /* identify delay id with largest allowance */
    DelayId largestAllowance = mostBytesAllowed ();
    return largestAllowance.bytesWanted(0, max);
#else

    return max;
#endif
}

void
MemObject::setNoDelay(bool const newValue)
{
#if DELAY_POOLS

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

#if DELAY_POOLS
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

        if (sc->getType() != STORE_MEM_CLIENT)
            /* reading off disk */
            continue;

        j = sc->delayId.bytesWanted(0, sc->copyInto.length);

        if (j > jmax) {
            jmax = j;
            result = sc->delayId;
        }
    }

    return result;
}

#endif
