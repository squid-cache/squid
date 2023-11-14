/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 90    Storage Manager Client-Side Interface */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "base/AsyncCbdataCalls.h"
#include "base/CodeContext.h"
#include "event.h"
#include "globals.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "MemObject.h"
#include "mime_header.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "StatCounters.h"
#include "Store.h"
#include "store/SwapMetaIn.h"
#include "store_swapin.h"
#include "StoreClient.h"
#if USE_DELAY_POOLS
#include "DelayPools.h"
#endif

/*
 * NOTE: 'Header' refers to the swapfile metadata header.
 *   'OBJHeader' refers to the object header, with canonical
 *   processed object headers (which may derive from FTP/HTTP etc
 *   upstream protocols
 *       'Body' refers to the swapfile body, which is the full
 *        HTTP reply (including HTTP headers and body).
 */
static StoreIOState::STRCB storeClientReadBody;
static StoreIOState::STRCB storeClientReadHeader;
static void storeClientCopy2(StoreEntry * e, store_client * sc);
static bool CheckQuickAbortIsReasonable(StoreEntry * entry);

CBDATA_CLASS_INIT(store_client);

/* StoreClient */

bool
StoreClient::onCollapsingPath() const
{
    if (!Config.onoff.collapsed_forwarding)
        return false;

    if (!Config.accessList.collapsedForwardingAccess)
        return true;

    ACLFilledChecklist checklist(Config.accessList.collapsedForwardingAccess, nullptr, nullptr);
    fillChecklist(checklist);
    return checklist.fastCheck().allowed();
}

bool
StoreClient::startCollapsingOn(const StoreEntry &e, const bool doingRevalidation) const
{
    if (!e.hittingRequiresCollapsing())
        return false; // collapsing is impossible due to the entry state

    if (!onCollapsingPath())
        return false; // collapsing is impossible due to Squid configuration

    /* collapsing is possible; the caller must collapse */

    if (const auto tags = loggingTags()) {
        if (doingRevalidation)
            tags->collapsingHistory.revalidationCollapses++;
        else
            tags->collapsingHistory.otherCollapses++;
    }

    debugs(85, 5, e << " doingRevalidation=" << doingRevalidation);
    return true;
}

/* store_client */

int
store_client::getType() const
{
    return type;
}

#if STORE_CLIENT_LIST_DEBUG
static store_client *
storeClientListSearch(const MemObject * mem, void *data)
{
    dlink_node *node;
    store_client *sc = nullptr;

    for (node = mem->clients.head; node; node = node->next) {
        sc = node->data;

        if (sc->owner == data)
            return sc;
    }

    return nullptr;
}

int
storeClientIsThisAClient(store_client * sc, void *someClient)
{
    return sc->owner == someClient;
}

#endif
#include "HttpRequest.h"

/* add client with fd to client list */
store_client *
storeClientListAdd(StoreEntry * e, void *data)
{
    MemObject *mem = e->mem_obj;
    store_client *sc;
    assert(mem);
#if STORE_CLIENT_LIST_DEBUG

    if (storeClientListSearch(mem, data) != NULL)
        /* XXX die! */
        assert(1 == 0);
#else
    (void)data;
#endif

    sc = new store_client (e);

    mem->addClient(sc);

    return sc;
}

/// finishCallback() wrapper; TODO: Add NullaryMemFunT for non-jobs.
void
store_client::FinishCallback(store_client * const sc)
{
    sc->finishCallback();
}

/// finishes a copy()-STCB sequence by synchronously calling STCB
void
store_client::finishCallback()
{
    Assure(_callback.callback_handler);
    Assure(_callback.notifier);

    // XXX: Some legacy code relies on zero-length buffers having nil data
    // pointers. Some other legacy code expects "correct" result.offset even
    // when there is no body to return. Accommodate all those expectations.
    auto result = StoreIOBuffer(0, copyInto.offset, nullptr);
    if (object_ok && parsingBuffer && parsingBuffer->contentSize())
        result = parsingBuffer->packBack();
    result.flags.error = object_ok ? 0 : 1;

    // TODO: Move object_ok handling above into this `if` statement.
    if (object_ok) {
        // works for zero hdr_sz cases as well; see also: nextHttpReadOffset()
        discardableHttpEnd_ = NaturalSum<int64_t>(entry->mem().baseReply().hdr_sz, result.offset, result.length).value();
    } else {
        // object_ok is sticky, so we will not be able to use any response bytes
        discardableHttpEnd_ = entry->mem().endOffset();
    }
    debugs(90, 7, "with " << result << "; discardableHttpEnd_=" << discardableHttpEnd_);

    // no HTTP headers and no body bytes (but not because there was no space)
    atEof_ = !sendingHttpHeaders() && !result.length && copyInto.length;

    parsingBuffer.reset();
    ++answers;

    STCB *temphandler = _callback.callback_handler;
    const auto cbdata = _callback.cbData.validDone();
    _callback = Callback();
    copyInto.data = nullptr;

    if (cbdata)
        temphandler(cbdata, result);
}

store_client::store_client(StoreEntry *e) :
#if STORE_CLIENT_LIST_DEBUG
    owner(cbdataReference(data)),
#endif
    entry(e),
    type(e->storeClientType()),
    object_ok(true),
    atEof_(false),
    answers(0)
{
    Assure(entry);
    entry->lock("store_client");

    flags.disk_io_pending = false;
    flags.store_copying = false;
    ++ entry->refcount;

    if (getType() == STORE_DISK_CLIENT) {
        /* assert we'll be able to get the data we want */
        /* maybe we should open swapin_sio here */
        assert(entry->hasDisk() && !entry->swapoutFailed());
    }
}

store_client::~store_client()
{
    assert(entry);
    entry->unlock("store_client");
}

/* copy bytes requested by the client */
void
storeClientCopy(store_client * sc,
                StoreEntry * e,
                StoreIOBuffer copyInto,
                STCB * callback,
                void *data)
{
    assert (sc != nullptr);
    sc->copy(e, copyInto,callback,data);
}

void
store_client::copy(StoreEntry * anEntry,
                   StoreIOBuffer copyRequest,
                   STCB * callback_fn,
                   void *data)
{
    assert (anEntry == entry);
    assert (callback_fn);
    assert (data);
    assert(!EBIT_TEST(entry->flags, ENTRY_ABORTED));
    debugs(90, 3, "store_client::copy: " << entry->getMD5Text() << ", from " <<
           copyRequest.offset << ", for length " <<
           (int) copyRequest.length << ", cb " << callback_fn << ", cbdata " <<
           data);

#if STORE_CLIENT_LIST_DEBUG

    assert(this == storeClientListSearch(entry->mem_obj, data));
#endif

    assert(!_callback.pending());
    _callback = Callback(callback_fn, data);
    copyInto.data = copyRequest.data;
    copyInto.length = copyRequest.length;
    copyInto.offset = copyRequest.offset;
    Assure(copyInto.offset >= 0);

    if (!copyInto.length) {
        // During the first storeClientCopy() call, a zero-size buffer means
        // that we will have to drop any HTTP response body bytes we read (with
        // the HTTP headers from disk). After that, it means we cannot return
        // anything to the caller at all.
        debugs(90, 2, "WARNING: zero-size storeClientCopy() buffer: " << copyInto);
        // keep going; moreToRead() should prevent any from-Store reading
    }

    // Our nextHttpReadOffset() expects the first copy() call to have zero
    // offset. More complex code could handle a positive first offset, but it
    // would only be useful when reading responses from memory: We would not
    // _delay_ the response (to read the requested HTTP body bytes from disk)
    // when we already can respond with HTTP headers.
    Assure(!copyInto.offset || answeredOnce());

    parsingBuffer.emplace(copyInto);

    discardableHttpEnd_ = nextHttpReadOffset();
    debugs(90, 7, "discardableHttpEnd_=" << discardableHttpEnd_);

    static bool copying (false);
    assert (!copying);
    copying = true;
    /* we might be blocking comm reads due to readahead limits
     * now we have a new offset, trigger those reads...
     */
    entry->mem_obj->kickReads();
    copying = false;

    anEntry->lock("store_client::copy"); // see deletion note below

    storeClientCopy2(entry, this);

    // Bug 3480: This store_client object may be deleted now if, for example,
    // the client rejects the hit response copied above. Use on-stack pointers!

#if USE_ADAPTATION
    anEntry->kickProducer();
#endif
    anEntry->unlock("store_client::copy");

    // Add no code here. This object may no longer exist.
}

/// Whether Store has (or possibly will have) more entry data for us.
bool
store_client::moreToRead() const
{
    if (!copyInto.length)
        return false; // the client supplied a zero-size buffer

    if (entry->store_status == STORE_PENDING)
        return true; // there may be more coming

    /* STORE_OK, including aborted entries: no more data is coming */

    if (canReadFromMemory())
        return true; // memory has the first byte wanted by the client

    if (!entry->hasDisk())
        return false; // cannot read anything from disk either

    if (entry->objectLen() >= 0 && copyInto.offset >= entry->contentLen())
        return false; // the disk cannot have byte(s) wanted by the client

    // we cannot be sure until we swap in metadata and learn contentLen(),
    // but the disk may have the byte(s) wanted by the client
    return true;
}

static void
storeClientCopy2(StoreEntry * e, store_client * sc)
{
    /* reentrancy not allowed  - note this could lead to
     * dropped notifications about response data availability
     */

    if (sc->flags.store_copying) {
        debugs(90, 3, "prevented recursive copying for " << *e);
        return;
    }

    debugs(90, 3, "storeClientCopy2: " << e->getMD5Text());
    assert(sc->_callback.pending());
    /*
     * We used to check for ENTRY_ABORTED here.  But there were some
     * problems.  For example, we might have a slow client (or two) and
     * the peer server is reading far ahead and swapping to disk.  Even
     * if the peer aborts, we want to give the client(s)
     * everything we got before the abort condition occurred.
     */
    sc->doCopy(e);
}

/// Whether our answer, if sent right now, will announce the availability of
/// HTTP response headers (to the STCB callback) for the first time.
bool
store_client::sendingHttpHeaders() const
{
    return !answeredOnce() && entry->mem().baseReply().hdr_sz > 0;
}

void
store_client::doCopy(StoreEntry *anEntry)
{
    Assure(_callback.pending());
    Assure(!flags.disk_io_pending);
    Assure(!flags.store_copying);

    assert (anEntry == entry);
    flags.store_copying = true;
    MemObject *mem = entry->mem_obj;

    debugs(33, 5, this << " into " << copyInto <<
           " hi: " << mem->endOffset() <<
           " objectLen: " << entry->objectLen() <<
           " past_answers: " << answers);

    const auto sendHttpHeaders = sendingHttpHeaders();

    if (!sendHttpHeaders && !moreToRead()) {
        /* There is no more to send! */
        debugs(33, 3, "There is no more to send!");
        noteNews();
        flags.store_copying = false;
        return;
    }

    if (!sendHttpHeaders && anEntry->store_status == STORE_PENDING && nextHttpReadOffset() >= mem->endOffset()) {
        debugs(90, 3, "store_client::doCopy: Waiting for more");
        flags.store_copying = false;
        return;
    }

    /*
     * Slight weirdness here.  We open a swapin file for any
     * STORE_DISK_CLIENT, even if we can copy the requested chunk
     * from memory in the next block.  We must try to open the
     * swapin file before sending any data to the client side.  If
     * we postpone the open, and then can not open the file later
     * on, the client loses big time.  Its transfer just gets cut
     * off.  Better to open it early (while the client side handler
     * is clientCacheHit) so that we can fall back to a cache miss
     * if needed.
     */

    if (STORE_DISK_CLIENT == getType() && swapin_sio == nullptr) {
        if (!startSwapin())
            return; // failure
    }

    // Send any immediately available body bytes unless we sendHttpHeaders.
    // TODO: Send those body bytes when we sendHttpHeaders as well.
    if (!sendHttpHeaders && canReadFromMemory()) {
        readFromMemory();
        noteNews(); // will sendHttpHeaders (if needed) as well
        flags.store_copying = false;
        return;
    }

    if (sendHttpHeaders) {
        debugs(33, 5, "just send HTTP headers: " << mem->baseReply().hdr_sz);
        noteNews();
        flags.store_copying = false;
        return;
    }

    // no information that the client needs is available immediately
    scheduleDiskRead();
}

/// opens the swapin "file" if possible; otherwise, fail()s and returns false
bool
store_client::startSwapin()
{
    debugs(90, 3, "store_client::doCopy: Need to open swap in file");
    /* gotta open the swapin file */

    if (storeTooManyDiskFilesOpen()) {
        /* yuck -- this causes a TCP_SWAPFAIL_MISS on the client side */
        fail();
        flags.store_copying = false;
        return false;
    } else if (!flags.disk_io_pending) {
        /* Don't set store_io_pending here */
        storeSwapInStart(this);

        if (swapin_sio == nullptr) {
            fail();
            flags.store_copying = false;
            return false;
        }

        return true;
    } else {
        debugs(90, DBG_IMPORTANT, "WARNING: Averted multiple fd operation (1)");
        flags.store_copying = false;
        return false;
    }
}

void
store_client::noteSwapInDone(const bool error)
{
    Assure(_callback.pending());
    if (error)
        fail();
    else
        noteNews();
}

void
store_client::scheduleDiskRead()
{
    /* What the client wants is not in memory. Schedule a disk read */
    if (getType() == STORE_DISK_CLIENT) {
        // we should have called startSwapin() already
        assert(swapin_sio != nullptr);
    } else if (!swapin_sio && !startSwapin()) {
        debugs(90, 3, "bailing after swapin start failure for " << *entry);
        assert(!flags.store_copying);
        return;
    }

    assert(!flags.disk_io_pending);

    debugs(90, 3, "reading " << *entry << " from disk");

    fileRead();

    flags.store_copying = false;
}

/// whether at least one byte wanted by the client is in memory
bool
store_client::canReadFromMemory() const
{
    const auto &mem = entry->mem();
    const auto memReadOffset = nextHttpReadOffset();
    // XXX: This (lo <= offset < end) logic does not support Content-Range gaps.
    return mem.inmem_lo <= memReadOffset && memReadOffset < mem.endOffset() &&
           parsingBuffer->spaceSize();
}

/// The offset of the next stored HTTP response byte wanted by the client.
int64_t
store_client::nextHttpReadOffset() const
{
    Assure(parsingBuffer);
    const auto &mem = entry->mem();
    const auto hdr_sz = mem.baseReply().hdr_sz;
    // Certain SMP cache manager transactions do not store HTTP headers in
    // mem_hdr; they store just a kid-specific piece of the future report body.
    // In such cases, hdr_sz ought to be zero. In all other (known) cases,
    // mem_hdr contains HTTP response headers (positive hdr_sz if parsed)
    // followed by HTTP response body. This code math accommodates all cases.
    return NaturalSum<int64_t>(hdr_sz, copyInto.offset, parsingBuffer->contentSize()).value();
}

/// Copies at least some of the requested body bytes from MemObject memory,
/// satisfying the copy() request.
/// \pre canReadFromMemory() is true
void
store_client::readFromMemory()
{
    Assure(parsingBuffer);
    const auto readInto = parsingBuffer->space().positionAt(nextHttpReadOffset());

    debugs(90, 3, "copying HTTP body bytes from memory into " << readInto);
    const auto sz = entry->mem_obj->data_hdr.copy(readInto);
    Assure(sz > 0); // our canReadFromMemory() precondition guarantees that
    parsingBuffer->appended(readInto.data, sz);
}

void
store_client::fileRead()
{
    MemObject *mem = entry->mem_obj;

    assert(_callback.pending());
    assert(!flags.disk_io_pending);
    flags.disk_io_pending = true;

    // mem->swap_hdr_sz is zero here during initial read(s)
    const auto nextStoreReadOffset = NaturalSum<int64_t>(mem->swap_hdr_sz, nextHttpReadOffset()).value();

    // XXX: If fileRead() is called when we do not yet know mem->swap_hdr_sz,
    // then we must start reading from disk offset zero to learn it: we cannot
    // compute correct HTTP response start offset on disk without it. However,
    // late startSwapin() calls imply that the assertion below might fail.
    Assure(mem->swap_hdr_sz > 0 || !nextStoreReadOffset);

    // TODO: Remove this assertion. Introduced in 1998 commit 3157c72, it
    // assumes that swapped out memory is freed unconditionally, but we no
    // longer do that because trimMemory() path checks lowestMemReaderOffset().
    // It is also misplaced: We are not swapping out anything here and should
    // not care about any swapout invariants.
    if (mem->swap_hdr_sz != 0)
        if (entry->swappingOut())
            assert(mem->swapout.sio->offset() > nextStoreReadOffset);

    // XXX: We should let individual cache_dirs limit the read size instead, but
    // we cannot do that without more fixes and research because:
    // * larger reads corrupt responses when cache_dir uses SharedMemory::get();
    // * we do not know how to find all I/O code that assumes this limit;
    // * performance effects of larger disk reads may be negative somewhere.
    const decltype(StoreIOBuffer::length) maxReadSize = SM_PAGE_SIZE;

    Assure(parsingBuffer);
    // also, do not read more than we can return (via a copyInto.length buffer)
    const auto readSize = std::min(copyInto.length, maxReadSize);
    lastDiskRead = parsingBuffer->makeSpace(readSize).positionAt(nextStoreReadOffset);
    debugs(90, 5, "into " << lastDiskRead);

    storeRead(swapin_sio,
              lastDiskRead.data,
              lastDiskRead.length,
              lastDiskRead.offset,
              mem->swap_hdr_sz == 0 ? storeClientReadHeader
              : storeClientReadBody,
              this);
}

void
store_client::readBody(const char * const buf, const ssize_t lastIoResult)
{
    Assure(flags.disk_io_pending);
    flags.disk_io_pending = false;
    assert(_callback.pending());
    Assure(parsingBuffer);
    debugs(90, 3, "got " << lastIoResult << " using " << *parsingBuffer);

    if (lastIoResult < 0)
        return fail();

    if (!lastIoResult) {
        if (answeredOnce())
            return noteNews();

        debugs(90, DBG_CRITICAL, "ERROR: Truncated HTTP headers in on-disk object");
        return fail();
    }

    assert(lastDiskRead.data == buf);
    lastDiskRead.length = lastIoResult;

    parsingBuffer->appended(buf, lastIoResult);

    // we know swap_hdr_sz by now and were reading beyond swap metadata because
    // readHead() would have been called otherwise (to read swap metadata)
    const auto swap_hdr_sz = entry->mem().swap_hdr_sz;
    Assure(swap_hdr_sz > 0);
    Assure(!Less(lastDiskRead.offset, swap_hdr_sz));

    // Map lastDiskRead (i.e. the disk area we just read) to an HTTP reply part.
    // The bytes are the same, but disk and HTTP offsets differ by swap_hdr_sz.
    const auto httpOffset = lastDiskRead.offset - swap_hdr_sz;
    const auto httpPart = StoreIOBuffer(lastDiskRead).positionAt(httpOffset);

    maybeWriteFromDiskToMemory(httpPart);
    handleBodyFromDisk();
}

/// de-serializes HTTP response (partially) read from disk storage
void
store_client::handleBodyFromDisk()
{
    // We cannot de-serialize on-disk HTTP response without MemObject because
    // without MemObject::swap_hdr_sz we cannot know where that response starts.
    Assure(entry->mem_obj);
    Assure(entry->mem_obj->swap_hdr_sz > 0);

    if (!answeredOnce()) {
        // All on-disk responses have HTTP headers. First disk body read(s)
        // include HTTP headers that we must parse (if needed) and skip.
        const auto haveHttpHeaders = entry->mem_obj->baseReply().pstate == Http::Message::psParsed;
        if (!haveHttpHeaders && !parseHttpHeadersFromDisk())
            return;
        skipHttpHeadersFromDisk();
    }

    noteNews();
}

/// Adds HTTP response data loaded from disk to the memory cache (if
/// needed/possible). The given part may contain portions of HTTP response
/// headers and/or HTTP response body.
void
store_client::maybeWriteFromDiskToMemory(const StoreIOBuffer &httpResponsePart)
{
    // XXX: Reject [memory-]uncachable/unshareable responses instead of assuming
    // that an HTTP response should be written to MemObject's data_hdr (and that
    // it may purge already cached entries) just because it "fits" and was
    // loaded from disk. For example, this response may already be marked for
    // release. The (complex) cachability decision(s) should be made outside
    // (and obeyed by) this low-level code.
    if (httpResponsePart.length && entry->mem_obj->inmem_lo == 0 && entry->objectLen() <= (int64_t)Config.Store.maxInMemObjSize && Config.onoff.memory_cache_disk) {
        storeGetMemSpace(httpResponsePart.length);
        // XXX: This "recheck" is not needed because storeGetMemSpace() cannot
        // purge mem_hdr bytes of a locked entry, and we do lock ours. And
        // inmem_lo offset itself should not be relevant to appending new bytes.
        //
        // recheck for the above call may purge entry's data from the memory cache
        if (entry->mem_obj->inmem_lo == 0) {
            // XXX: This code assumes a non-shared memory cache.
            if (httpResponsePart.offset == entry->mem_obj->endOffset())
                entry->mem_obj->write(httpResponsePart);
        }
    }
}

void
store_client::fail()
{
    debugs(90, 3, (object_ok ? "once" : "again"));
    if (!object_ok)
        return; // we failed earlier; nothing to do now

    object_ok = false;

    noteNews();
}

/// if necessary and possible, informs the Store reader about copy() result
void
store_client::noteNews()
{
    /* synchronous open failures callback from the store,
     * before startSwapin detects the failure.
     * TODO: fix this inconsistent behaviour - probably by
     * having storeSwapInStart become a callback functions,
     * not synchronous
     */

    if (!_callback.callback_handler) {
        debugs(90, 5, "client lost interest");
        return;
    }

    if (_callback.notifier) {
        debugs(90, 5, "earlier news is being delivered by " << _callback.notifier);
        return;
    }

    _callback.notifier = asyncCall(90, 4, "store_client::FinishCallback", cbdataDialer(store_client::FinishCallback, this));
    ScheduleCallHere(_callback.notifier);

    Assure(!_callback.pending());
}

static void
storeClientReadHeader(void *data, const char *buf, ssize_t len, StoreIOState::Pointer)
{
    store_client *sc = (store_client *)data;
    sc->readHeader(buf, len);
}

static void
storeClientReadBody(void *data, const char *buf, ssize_t len, StoreIOState::Pointer)
{
    store_client *sc = (store_client *)data;
    sc->readBody(buf, len);
}

void
store_client::readHeader(char const *buf, ssize_t len)
{
    MemObject *const mem = entry->mem_obj;

    assert(flags.disk_io_pending);
    flags.disk_io_pending = false;
    assert(_callback.pending());

    // abort if we fail()'d earlier
    if (!object_ok)
        return;

    Assure(parsingBuffer);
    debugs(90, 3, "got " << len << " using " << *parsingBuffer);

    if (len < 0)
        return fail();

    try {
        Assure(!parsingBuffer->contentSize());
        parsingBuffer->appended(buf, len);
        Store::UnpackHitSwapMeta(buf, len, *entry);
        parsingBuffer->consume(mem->swap_hdr_sz);
    } catch (...) {
        debugs(90, DBG_IMPORTANT, "ERROR: Failed to unpack Store entry metadata: " << CurrentException);
        fail();
        return;
    }

    maybeWriteFromDiskToMemory(parsingBuffer->content());
    handleBodyFromDisk();
}

/*
 * This routine hasn't been optimised to take advantage of the
 * passed sc. Yet.
 */
int
storeUnregister(store_client * sc, StoreEntry * e, void *data)
{
    MemObject *mem = e->mem_obj;
#if STORE_CLIENT_LIST_DEBUG
    assert(sc == storeClientListSearch(e->mem_obj, data));
#else
    (void)data;
#endif

    if (mem == nullptr)
        return 0;

    debugs(90, 3, "storeUnregister: called for '" << e->getMD5Text() << "'");

    if (sc == nullptr) {
        debugs(90, 3, "storeUnregister: No matching client for '" << e->getMD5Text() << "'");
        return 0;
    }

    if (mem->clientCount() == 0) {
        debugs(90, 3, "storeUnregister: Consistency failure - store client being unregistered is not in the mem object's list for '" << e->getMD5Text() << "'");
        return 0;
    }

    dlinkDelete(&sc->node, &mem->clients);
    -- mem->nclients;

    const auto swapoutFinished = e->swappedOut() || e->swapoutFailed();
    if (e->store_status == STORE_OK && !swapoutFinished)
        e->swapOut();

    if (sc->swapin_sio != nullptr) {
        storeClose(sc->swapin_sio, StoreIOState::readerDone);
        sc->swapin_sio = nullptr;
        ++statCounter.swap.ins;
    }

    if (sc->_callback.callback_handler || sc->_callback.notifier) {
        debugs(90, 3, "forgetting store_client callback for " << *e);
        // Do not notify: Callers want to stop copying and forget about this
        // pending copy request. Some would mishandle a notification from here.
        if (sc->_callback.notifier)
            sc->_callback.notifier->cancel("storeUnregister");
    }

#if STORE_CLIENT_LIST_DEBUG
    cbdataReferenceDone(sc->owner);

#endif

    // We must lock to safely dereference e below, after deleting sc and after
    // calling CheckQuickAbortIsReasonable().
    e->lock("storeUnregister");

    // XXX: We might be inside sc store_client method somewhere up the call
    // stack. TODO: Convert store_client to AsyncJob to make destruction async.
    delete sc;

    if (CheckQuickAbortIsReasonable(e))
        e->abort();
    else
        mem->kickReads();

#if USE_ADAPTATION
    e->kickProducer();
#endif

    e->unlock("storeUnregister");
    return 1;
}

/* Call handlers waiting for  data to be appended to E. */
void
StoreEntry::invokeHandlers()
{
    if (EBIT_TEST(flags, DELAY_SENDING)) {
        debugs(90, 3, "DELAY_SENDING is on, exiting " << *this);
        return;
    }
    if (EBIT_TEST(flags, ENTRY_FWD_HDR_WAIT)) {
        debugs(90, 3, "ENTRY_FWD_HDR_WAIT is on, exiting " << *this);
        return;
    }

    /* Commit what we can to disk, if appropriate */
    swapOut();
    int i = 0;
    store_client *sc;
    dlink_node *nx = nullptr;
    dlink_node *node;

    debugs(90, 3, mem_obj->nclients << " clients; " << *this << ' ' << getMD5Text());
    /* walk the entire list looking for valid callbacks */

    const auto savedContext = CodeContext::Current();
    for (node = mem_obj->clients.head; node; node = nx) {
        sc = (store_client *)node->data;
        nx = node->next;
        ++i;

        if (!sc->_callback.pending())
            continue;

        if (sc->flags.disk_io_pending)
            continue;

        if (sc->flags.store_copying)
            continue;

        // XXX: If invokeHandlers() is (indirectly) called from a store_client
        // method, then the above three conditions may not be sufficient to
        // prevent us from reentering the same store_client object! This
        // probably does not happen in the current code, but no observed
        // invariant prevents this from (accidentally) happening in the future.

        // TODO: Convert store_client into AsyncJob; make this call asynchronous
        CodeContext::Reset(sc->_callback.codeContext);
        debugs(90, 3, "checking client #" << i);
        storeClientCopy2(this, sc);
    }
    CodeContext::Reset(savedContext);
}

// Does not account for remote readers/clients.
int
storePendingNClients(const StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    int npend = nullptr == mem ? 0 : mem->nclients;
    debugs(90, 3, "storePendingNClients: returning " << npend);
    return npend;
}

/* return true if the request should be aborted */
static bool
CheckQuickAbortIsReasonable(StoreEntry * entry)
{
    assert(entry);
    debugs(90, 3, "entry=" << *entry);

    if (storePendingNClients(entry) > 0) {
        debugs(90, 3, "quick-abort? NO storePendingNClients() > 0");
        return false;
    }

    if (Store::Root().transientReaders(*entry)) {
        debugs(90, 3, "quick-abort? NO still have one or more transient readers");
        return false;
    }

    if (entry->store_status != STORE_PENDING) {
        debugs(90, 3, "quick-abort? NO store_status != STORE_PENDING");
        return false;
    }

    if (EBIT_TEST(entry->flags, ENTRY_SPECIAL)) {
        debugs(90, 3, "quick-abort? NO ENTRY_SPECIAL");
        return false;
    }

    if (shutting_down) {
        debugs(90, 3, "quick-abort? YES avoid heavy optional work during shutdown");
        return true;
    }

    MemObject * const mem = entry->mem_obj;
    assert(mem);
    debugs(90, 3, "mem=" << mem);

    if (mem->request && !mem->request->flags.cachable) {
        debugs(90, 3, "quick-abort? YES !mem->request->flags.cachable");
        return true;
    }

    if (EBIT_TEST(entry->flags, KEY_PRIVATE)) {
        debugs(90, 3, "quick-abort? YES KEY_PRIVATE");
        return true;
    }

    const auto &reply = mem->baseReply();

    if (reply.hdr_sz <= 0) {
        // TODO: Check whether this condition works for HTTP/0 responses.
        debugs(90, 3, "quick-abort? YES no object data received yet");
        return true;
    }

    if (Config.quickAbort.min < 0) {
        debugs(90, 3, "quick-abort? NO disabled");
        return false;
    }

    if (mem->request && mem->request->range && mem->request->getRangeOffsetLimit() < 0) {
        // the admin has configured "range_offset_limit none"
        debugs(90, 3, "quick-abort? NO admin configured range replies to full-download");
        return false;
    }

    if (reply.content_length < 0) {
        // XXX: cf.data.pre does not document what should happen in this case
        // We know that quick_abort is enabled, but no limit can be applied.
        debugs(90, 3, "quick-abort? YES unknown content length");
        return true;
    }
    const auto expectlen = reply.hdr_sz + reply.content_length;

    int64_t curlen =  mem->endOffset();

    if (curlen > expectlen) {
        debugs(90, 3, "quick-abort? YES bad content length (" << curlen << " of " << expectlen << " bytes received)");
        return true;
    }

    if ((expectlen - curlen) < (Config.quickAbort.min << 10)) {
        debugs(90, 3, "quick-abort? NO only a little more object left to receive");
        return false;
    }

    if ((expectlen - curlen) > (Config.quickAbort.max << 10)) {
        debugs(90, 3, "quick-abort? YES too much left to go");
        return true;
    }

    // XXX: This is absurd! TODO: For positives, "a/(b/c) > d" is "a*c > b*d".
    if (expectlen < 100) {
        debugs(90, 3, "quick-abort? NO avoid FPE");
        return false;
    }

    if ((curlen / (expectlen / 100)) > (Config.quickAbort.pct)) {
        debugs(90, 3, "quick-abort? NO past point of no return");
        return false;
    }

    debugs(90, 3, "quick-abort? YES default");
    return true;
}

/// parses HTTP header bytes loaded from disk
/// \returns false if fail() or scheduleDiskRead() has been called and, hence,
/// the caller should just quit without any further action
bool
store_client::parseHttpHeadersFromDisk()
{
    try {
        return tryParsingHttpHeaders();
    } catch (...) {
        // XXX: Our parser enforces Config.maxReplyHeaderSize limit, but our
        // packer does not. Since packing might increase header size, we may
        // cache a header that we cannot parse and get here. Same for MemStore.
        debugs(90, DBG_CRITICAL, "ERROR: Cannot parse on-disk HTTP headers" <<
               Debug::Extra << "exception: " << CurrentException <<
               Debug::Extra << "raw input size: " << parsingBuffer->contentSize() << " bytes" <<
               Debug::Extra << "current buffer capacity: " << parsingBuffer->capacity() << " bytes");
        fail();
        return false;
    }
}

/// parseHttpHeadersFromDisk() helper
/// \copydoc parseHttpHeaders()
bool
store_client::tryParsingHttpHeaders()
{
    Assure(parsingBuffer);
    Assure(!copyInto.offset); // otherwise, parsingBuffer cannot have HTTP response headers
    auto &adjustableReply = entry->mem().adjustableBaseReply();
    if (adjustableReply.parseTerminatedPrefix(parsingBuffer->c_str(), parsingBuffer->contentSize()))
        return true;

    // TODO: Optimize by checking memory as well. For simplicity sake, we
    // continue on the disk-reading path, but readFromMemory() can give us the
    // missing header bytes immediately if a concurrent request put those bytes
    // into memory while we were waiting for our disk response.
    scheduleDiskRead();
    return false;
}

/// skips HTTP header bytes previously loaded from disk
void
store_client::skipHttpHeadersFromDisk()
{
    const auto hdr_sz = entry->mem_obj->baseReply().hdr_sz;
    Assure(hdr_sz > 0); // all on-disk responses have HTTP headers
    if (Less(parsingBuffer->contentSize(), hdr_sz)) {
        debugs(90, 5, "discovered " << hdr_sz << "-byte HTTP headers in memory after reading some of them from disk: " << *parsingBuffer);
        parsingBuffer->consume(parsingBuffer->contentSize()); // skip loaded HTTP header prefix
    } else {
        parsingBuffer->consume(hdr_sz); // skip loaded HTTP headers
        const auto httpBodyBytesAfterHeader = parsingBuffer->contentSize(); // may be zero
        Assure(httpBodyBytesAfterHeader <= copyInto.length);
        debugs(90, 5, "read HTTP body prefix: " << httpBodyBytesAfterHeader);
    }
}

void
store_client::dumpStats(MemBuf * output, int clientNumber) const
{
    if (_callback.pending())
        return;

    output->appendf("\tClient #%d, %p\n", clientNumber, this);
    output->appendf("\t\tcopy_offset: %" PRId64 "\n", copyInto.offset);
    output->appendf("\t\tcopy_size: %" PRIuSIZE "\n", copyInto.length);
    output->append("\t\tflags:", 8);

    if (flags.disk_io_pending)
        output->append(" disk_io_pending", 16);

    if (flags.store_copying)
        output->append(" store_copying", 14);

    if (_callback.notifier)
        output->append(" notifying", 10);

    output->append("\n",1);
}

bool
store_client::Callback::pending() const
{
    return callback_handler && !notifier;
}

store_client::Callback::Callback(STCB *function, void *data):
    callback_handler(function),
    cbData(data),
    codeContext(CodeContext::Current())
{
}

#if USE_DELAY_POOLS
int
store_client::bytesWanted() const
{
    // TODO: To avoid using stale copyInto, return zero if !_callback.pending()?
    return delayId.bytesWanted(0, copyInto.length);
}

void
store_client::setDelayId(DelayId delay_id)
{
    delayId = delay_id;
}
#endif

