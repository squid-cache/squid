
/*
 * $Id: store_client.cc,v 1.117 2002/10/14 08:16:59 robertc Exp $
 *
 * DEBUG: section 20    Storage Manager Client-Side Interface
 * AUTHOR: Duane Wessels
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
#include "StoreClient.h"
#include "Store.h"


CBDATA_TYPE(store_client);

/*
 * NOTE: 'Header' refers to the swapfile metadata header.
 *       'Body' refers to the swapfile body, which is the full
 *        HTTP reply (including HTTP headers and body).
 */
static STRCB storeClientReadBody;
static STRCB storeClientReadHeader;
static void storeClientCopy2(StoreEntry * e, store_client * sc);
static void storeClientCopy3(StoreEntry * e, store_client * sc);
static void storeClientFileRead(store_client * sc);
static EVH storeClientCopyEvent;
static store_client_t storeClientType(StoreEntry *);
static int CheckQuickAbort2(StoreEntry * entry);
static void CheckQuickAbort(StoreEntry * entry);

#if STORE_CLIENT_LIST_DEBUG
static store_client *
storeClientListSearch(const MemObject * mem, void *data)
{
    dlink_node *node;
    store_client *sc = NULL;
    for (node = mem->clients.head; node; node = node->next) {
	sc = node->data;
	if (sc->owner == data)
	    return sc;
    }
    return NULL;
}

int
storeClientIsThisAClient(store_client * sc, void *someClient)
{
    return sc->owner == someClient;
}

#endif


static store_client_t
storeClientType(StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    if (mem->inmem_lo)
	return STORE_DISK_CLIENT;
    if (EBIT_TEST(e->flags, ENTRY_ABORTED)) {
	/* I don't think we should be adding clients to aborted entries */
	debug(20, 1) ("storeClientType: adding to ENTRY_ABORTED entry\n");
	return STORE_MEM_CLIENT;
    }
    if (e->store_status == STORE_OK) {
	if (mem->inmem_lo == 0 && mem->inmem_hi > 0)
	    return STORE_MEM_CLIENT;
	else
	    return STORE_DISK_CLIENT;
    }
    /* here and past, entry is STORE_PENDING */
    /*
     * If this is the first client, let it be the mem client
     */
    else if (mem->nclients == 1)
	return STORE_MEM_CLIENT;
    /*
     * If there is no disk file to open yet, we must make this a
     * mem client.  If we can't open the swapin file before writing
     * to the client, there is no guarantee that we will be able
     * to open it later when we really need it.
     */
    else if (e->swap_status == SWAPOUT_NONE)
	return STORE_MEM_CLIENT;
    /*
     * otherwise, make subsequent clients read from disk so they
     * can not delay the first, and vice-versa.
     */
    else
	return STORE_DISK_CLIENT;
}

/* add client with fd to client list */
store_client *
storeClientListAdd(StoreEntry * e, void *data)
{
    MemObject *mem = e->mem_obj;
    store_client *sc;
    assert(mem);
#if STORE_CLIENT_LIST_DEBUG
    if (storeClientListSearch(mem, data) != NULL)
	assert(1 == 0);		/* XXX die! */
#endif
    e->refcount++;
    mem->nclients++;
    CBDATA_INIT_TYPE(store_client);
    sc = cbdataAlloc(store_client);
#if STORE_CLIENT_LIST_DEBUG
    sc->owner = cbdataReference(data);
#endif
    sc->cmp_offset = 0;
    sc->flags.disk_io_pending = 0;
    sc->entry = e;
    sc->type = storeClientType(e);
    if (sc->type == STORE_DISK_CLIENT)
	/* assert we'll be able to get the data we want */
	/* maybe we should open swapin_fd here */
	assert(e->swap_filen > -1 || storeSwapOutAble(e));
    dlinkAdd(sc, &sc->node, &mem->clients);
#if DELAY_POOLS
    sc->delayId = 0;
#endif
    return sc;
}

static void
storeClientCallback(store_client * sc, ssize_t sz)
{
    STCB *callback = sc->callback;
    void *cbdata;
    StoreIOBuffer result =
    {
	{0}, sz, 0, sc->copyInto.data};
    if (sz < 0) {
	result.flags.error = 1;
	result.length = 0;
    }
    result.offset = sc->cmp_offset;
    assert(sc->callback);
    sc->cmp_offset = sc->copyInto.offset + sz;
    sc->callback = NULL;
    sc->copyInto.data = NULL;
    if (cbdataReferenceValidDone(sc->callback_data, &cbdata))
	callback(cbdata, result);
}

static void
storeClientCopyEvent(void *data)
{
    store_client *sc = (store_client *)data;
    debug(20, 3) ("storeClientCopyEvent: Running\n");
    sc->flags.copy_event_pending = 0;
    if (!sc->callback)
	return;
    storeClientCopy2(sc->entry, sc);
}

/* copy bytes requested by the client */
void
storeClientCopy(store_client * sc,
    StoreEntry * e,
    StoreIOBuffer copyInto,
    STCB * callback,
    void *data)
{
    assert(!EBIT_TEST(e->flags, ENTRY_ABORTED));
    debug(20, 3) ("storeClientCopy: %s, from %lu, for length %d, cb %p, cbdata %p\n",
	storeKeyText((const cache_key *)e->hash.key),
	(unsigned long) copyInto.offset,
	(int) copyInto.length,
	callback,
	data);
    assert(sc != NULL);
#if STORE_CLIENT_LIST_DEBUG
    assert(sc == storeClientListSearch(e->mem_obj, data));
#endif
    assert(sc->callback == NULL);
    assert(sc->entry == e);
    assert(sc->cmp_offset == copyInto.offset);
    sc->callback = callback;
    sc->callback_data = cbdataReference(data);
    sc->copyInto.data = copyInto.data;
    sc->copyInto.length = copyInto.length;
    sc->copyInto.offset = copyInto.offset;

    storeClientCopy2(e, sc);
}

/*
 * This function is used below to decide if we have any more data to
 * send to the client.  If the store_status is STORE_PENDING, then we
 * do have more data to send.  If its STORE_OK, then
 * we continue checking.  If the object length is negative, then we
 * don't know the real length and must open the swap file to find out.
 * If the length is >= 0, then we compare it to the requested copy
 * offset.
 */
static int
storeClientNoMoreToSend(StoreEntry * e, store_client * sc)
{
    ssize_t len;
    if (e->store_status == STORE_PENDING)
	return 0;
    if ((len = objectLen(e)) < 0)
	return 0;
    if (sc->copyInto.offset < len)
	return 0;
    return 1;
}

static void
storeClientCopy2(StoreEntry * e, store_client * sc)
{
    if (sc->flags.copy_event_pending) {
	return;
    }
    if (EBIT_TEST(e->flags, ENTRY_FWD_HDR_WAIT)) {
	debug(20, 5) ("storeClientCopy2: returning because ENTRY_FWD_HDR_WAIT set\n");
	return;
    }
    if (sc->flags.store_copying) {
	sc->flags.copy_event_pending = 1;
	debug(20, 3) ("storeClientCopy2: Queueing storeClientCopyEvent()\n");
	eventAdd("storeClientCopyEvent", storeClientCopyEvent, sc, 0.0, 0);
	return;
    }
    sc->flags.store_copying = 1;
    debug(20, 3) ("storeClientCopy2: %s\n", storeKeyText((const cache_key *)e->hash.key));
    assert(sc->callback != NULL);
    /*
     * We used to check for ENTRY_ABORTED here.  But there were some
     * problems.  For example, we might have a slow client (or two) and
     * the server-side is reading far ahead and swapping to disk.  Even
     * if the server-side aborts, we want to give the client(s)
     * everything we got before the abort condition occurred.
     */
    /* Warning: storeClientCopy3 may indirectly free sc in callbacks,
     * hence the cbdata reference to keep it active for the duration of
     * this function
     */
    cbdataInternalLock(sc);
    storeClientCopy3(e, sc);
    sc->flags.store_copying = 0;
    cbdataInternalUnlock(sc);
}

static void
storeClientCopy3(StoreEntry * e, store_client * sc)
{
    MemObject *mem = e->mem_obj;
    size_t sz;

    debug(33, 5) ("co: %lu, hi: %ld\n", (unsigned long) sc->copyInto.offset, (long int) mem->inmem_hi);

    if (storeClientNoMoreToSend(e, sc)) {
	/* There is no more to send! */
	storeClientCallback(sc, 0);
	return;
    }
    /* Check that we actually have data */
    if (e->store_status == STORE_PENDING && sc->copyInto.offset >= mem->inmem_hi) {
	debug(20, 3) ("storeClientCopy3: Waiting for more\n");
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

    if (STORE_DISK_CLIENT == sc->type && NULL == sc->swapin_sio) {
	debug(20, 3) ("storeClientCopy3: Need to open swap in file\n");
	/* gotta open the swapin file */
	if (storeTooManyDiskFilesOpen()) {
	    /* yuck -- this causes a TCP_SWAPFAIL_MISS on the client side */
	    storeClientCallback(sc, -1);
	    return;
	} else if (!sc->flags.disk_io_pending) {
	    /* Don't set store_io_pending here */
	    storeSwapInStart(sc);
	    if (NULL == sc->swapin_sio) {
		storeClientCallback(sc, -1);
		return;
	    }
	    /*
	     * If the open succeeds we either copy from memory, or
	     * schedule a disk read in the next block.
	     */
	} else {
	    debug(20, 1) ("WARNING: Averted multiple fd operation (1)\n");
	    return;
	}
    }
    if (sc->copyInto.offset >= mem->inmem_lo && sc->copyInto.offset < mem->inmem_hi) {
	/* What the client wants is in memory */
	/* Old style */
	debug(20, 3) ("storeClientCopy3: Copying normal from memory\n");
	sz = stmemCopy(&mem->data_hdr, sc->copyInto.offset, sc->copyInto.data,
	    sc->copyInto.length);
	storeClientCallback(sc, sz);
	return;
    }
    /* What the client wants is not in memory. Schedule a disk read */
    assert(STORE_DISK_CLIENT == sc->type);
    assert(!sc->flags.disk_io_pending);
    debug(20, 3) ("storeClientCopy3: reading from STORE\n");
    storeClientFileRead(sc);
}

static void
storeClientFileRead(store_client * sc)
{
    MemObject *mem = sc->entry->mem_obj;

    assert(sc->callback != NULL);
    assert(!sc->flags.disk_io_pending);
    sc->flags.disk_io_pending = 1;
    if (mem->swap_hdr_sz == 0) {
	storeRead(sc->swapin_sio,
	    sc->copyInto.data,
	    sc->copyInto.length,
	    0,
	    storeClientReadHeader,
	    sc);
    } else {
	if (sc->entry->swap_status == SWAPOUT_WRITING)
	    assert(storeOffset(mem->swapout.sio) > sc->copyInto.offset + (off_t)mem->swap_hdr_sz);
	storeRead(sc->swapin_sio,
	    sc->copyInto.data,
	    sc->copyInto.length,
	    sc->copyInto.offset + mem->swap_hdr_sz,
	    storeClientReadBody,
	    sc);
    }
}

static void
storeClientReadBody(void *data, const char *buf, ssize_t len)
{
    store_client *sc = (store_client *)data;
    MemObject *mem = sc->entry->mem_obj;
    assert(sc->flags.disk_io_pending);
    sc->flags.disk_io_pending = 0;
    assert(sc->callback != NULL);
    debug(20, 3) ("storeClientReadBody: len %d\n", (int) len);
    if (sc->copyInto.offset == 0 && len > 0 && mem->reply->sline.status == 0)
	httpReplyParse(mem->reply, sc->copyInto.data, headersEnd(sc->copyInto.data, len));
    storeClientCallback(sc, len);
}

static void
storeClientReadHeader(void *data, const char *buf, ssize_t len)
{
    static int md5_mismatches = 0;
    store_client *sc = (store_client *)data;
    StoreEntry *e = sc->entry;
    MemObject *mem = e->mem_obj;
    int swap_hdr_sz = 0;
    size_t body_sz;
    size_t copy_sz;
    tlv *tlv_list;
    tlv *t;
    int swap_object_ok = 1;
    assert(sc->flags.disk_io_pending);
    sc->flags.disk_io_pending = 0;
    assert(sc->callback != NULL);
    debug(20, 3) ("storeClientReadHeader: len %d\n", (int) len);
    if (len < 0) {
	debug(20, 3) ("storeClientReadHeader: %s\n", xstrerror());
	storeClientCallback(sc, len);
	return;
    }
    tlv_list = storeSwapMetaUnpack(buf, &swap_hdr_sz);
    if (swap_hdr_sz > len) {
	/* oops, bad disk file? */
	debug(20, 1) ("WARNING: swapfile header too small\n");
	storeClientCallback(sc, -1);
	return;
    }
    if (tlv_list == NULL) {
	debug(20, 1) ("WARNING: failed to unpack meta data\n");
	storeClientCallback(sc, -1);
	return;
    }
    /*
     * Check the meta data and make sure we got the right object.
     */
    for (t = tlv_list; t && swap_object_ok; t = t->next) {
	switch (t->type) {
	case STORE_META_KEY:
	    assert(t->length == MD5_DIGEST_CHARS);
	    if (!EBIT_TEST(e->flags, KEY_PRIVATE) &&
		memcmp(t->value, e->hash.key, MD5_DIGEST_CHARS)) {
		debug(20, 2) ("storeClientReadHeader: swapin MD5 mismatch\n");
		debug(20, 2) ("\t%s\n", storeKeyText((const cache_key *)t->value));
		debug(20, 2) ("\t%s\n", storeKeyText((const cache_key *)e->hash.key));
		if (isPowTen(++md5_mismatches))
		    debug(20, 1) ("WARNING: %d swapin MD5 mismatches\n",
			md5_mismatches);
		swap_object_ok = 0;
	    }
	    break;
	case STORE_META_URL:
	    if (NULL == mem->url)
		(void) 0;	/* can't check */
	    else if (0 == strcasecmp(mem->url, (char *)t->value))
		(void) 0;	/* a match! */
	    else {
		debug(20, 1) ("storeClientReadHeader: URL mismatch\n");
		debug(20, 1) ("\t{%s} != {%s}\n", (char *) t->value, mem->url);
		swap_object_ok = 0;
		break;
	    }
	    break;
	case STORE_META_STD:
	    break;
	case STORE_META_VARY_HEADERS:
	    if (mem->vary_headers) {
		if (strcmp(mem->vary_headers, (char *)t->value) != 0)
		    swap_object_ok = 0;
	    } else {
		/* Assume the object is OK.. remember the vary request headers */
		mem->vary_headers = xstrdup((char *)t->value);
	    }
	    break;
	default:
	    debug(20, 1) ("WARNING: got unused STORE_META type %d\n", t->type);
	    break;
	}
    }
    storeSwapTLVFree(tlv_list);
    if (!swap_object_ok) {
	storeClientCallback(sc, -1);
	return;
    }
    mem->swap_hdr_sz = swap_hdr_sz;
    mem->object_sz = e->swap_file_sz - swap_hdr_sz;
    /*
     * If our last read got some data the client wants, then give
     * it to them, otherwise schedule another read.
     */
    body_sz = len - swap_hdr_sz;
    if (static_cast<size_t>(sc->copyInto.offset) < body_sz) {
	/*
	 * we have (part of) what they want
	 */
	copy_sz = XMIN(sc->copyInto.length, body_sz);
	debug(20, 3) ("storeClientReadHeader: copying %d bytes of body\n",
	    (int) copy_sz);
	xmemmove(sc->copyInto.data, sc->copyInto.data + swap_hdr_sz, copy_sz);
	if (sc->copyInto.offset == 0 && len > 0 && mem->reply->sline.status == 0)
	    httpReplyParse(mem->reply, sc->copyInto.data,
		headersEnd(sc->copyInto.data, copy_sz));
	storeClientCallback(sc, copy_sz);
	return;
    }
    /*
     * we don't have what the client wants, but at least we now
     * know the swap header size.
     */
    storeClientFileRead(sc);
}

int
storeClientCopyPending(store_client * sc, StoreEntry * e, void *data)
{
#if STORE_CLIENT_LIST_DEBUG
    assert(sc == storeClientListSearch(e->mem_obj, data));
#endif
#ifndef SILLY_CODE
    assert(sc);
#endif
    assert(sc->entry == e);
#if SILLY_CODE
    if (sc == NULL)
	return 0;
#endif
    if (sc->callback == NULL)
	return 0;
    return 1;
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
#endif
    if (mem == NULL)
	return 0;
    debug(20, 3) ("storeUnregister: called for '%s'\n", storeKeyText((const cache_key *)e->hash.key));
    if (sc == NULL)
	return 0;
    if (mem->clients.head == NULL)
	return 0;
    if (sc == mem->clients.head->data) {
	/*
	 * If we are unregistering the _first_ client for this
	 * entry, then we have to reset the client FD to -1.
	 */
	mem->fd = -1;
    }
    dlinkDelete(&sc->node, &mem->clients);
    mem->nclients--;
    if (e->store_status == STORE_OK && e->swap_status != SWAPOUT_DONE)
	storeSwapOut(e);
    if (sc->swapin_sio) {
	storeClose(sc->swapin_sio);
	cbdataReferenceDone(sc->swapin_sio);
	statCounter.swap.ins++;
    }
    if (NULL != sc->callback) {
	/* callback with ssize = -1 to indicate unexpected termination */
	debug(20, 3) ("storeUnregister: store_client for %s has a callback\n",
	    mem->url);
	storeClientCallback(sc, -1);
    }
#if DELAY_POOLS
    delayUnregisterDelayIdPtr(&sc->delayId);
#endif
#if STORE_CLIENT_LIST_DEBUG
    cbdataReferenceDone(sc->owner);
#endif
    cbdataFree(sc);
    assert(e->lock_count > 0);
    if (mem->nclients == 0)
	CheckQuickAbort(e);
    return 1;
}

off_t
storeLowestMemReaderOffset(const StoreEntry * entry)
{
    const MemObject *mem = entry->mem_obj;
    off_t lowest = mem->inmem_hi + 1;
    store_client *sc;
    dlink_node *nx = NULL;
    dlink_node *node;

    for (node = mem->clients.head; node; node = nx) {
	sc = (store_client *)node->data;
	nx = node->next;
	if (sc->type != STORE_MEM_CLIENT)
	    continue;
	if (sc->type == STORE_DISK_CLIENT)
	    if (NULL != sc->swapin_sio)
		continue;
	if (sc->copyInto.offset < lowest)
	    lowest = sc->copyInto.offset;
    }
    return lowest;
}

/* Call handlers waiting for  data to be appended to E. */
void
InvokeHandlers(StoreEntry * e)
{
    int i = 0;
    MemObject *mem = e->mem_obj;
    store_client *sc;
    dlink_node *nx = NULL;
    dlink_node *node;

    debug(20, 3) ("InvokeHandlers: %s\n", storeKeyText((const cache_key *)e->hash.key));
    /* walk the entire list looking for valid callbacks */
    for (node = mem->clients.head; node; node = nx) {
	sc = (store_client *)node->data;
	nx = node->next;
	debug(20, 3) ("InvokeHandlers: checking client #%d\n", i++);
	if (sc->callback_data == NULL)
	    continue;
	if (sc->callback == NULL)
	    continue;
	if (sc->flags.disk_io_pending)
	    continue;
	storeClientCopy2(e, sc);
    }
}

int
storePendingNClients(const StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    int npend = NULL == mem ? 0 : mem->nclients;
    debug(20, 3) ("storePendingNClients: returning %d\n", npend);
    return npend;
}

/* return 1 if the request should be aborted */
static int
CheckQuickAbort2(StoreEntry * entry)
{
    size_t curlen;
    size_t minlen;
    size_t expectlen;
    MemObject *mem = entry->mem_obj;
    assert(mem);
    debug(20, 3) ("CheckQuickAbort2: entry=%p, mem=%p\n", entry, mem);
    if (mem->request && !mem->request->flags.cachable) {
	debug(20, 3) ("CheckQuickAbort2: YES !mem->request->flags.cachable\n");
	return 1;
    }
    if (EBIT_TEST(entry->flags, KEY_PRIVATE)) {
	debug(20, 3) ("CheckQuickAbort2: YES KEY_PRIVATE\n");
	return 1;
    }
    expectlen = mem->reply->content_length + mem->reply->hdr_sz;
    assert (mem->reply->content_length + mem->reply->hdr_sz >= 0);
    curlen = (size_t) mem->inmem_hi;
    minlen = (size_t) Config.quickAbort.min << 10;
    if (minlen < 0) {
	debug(20, 3) ("CheckQuickAbort2: NO disabled\n");
	return 0;
    }
    if (curlen > expectlen) {
	debug(20, 3) ("CheckQuickAbort2: YES bad content length\n");
	return 1;
    }
    if ((expectlen - curlen) < minlen) {
	debug(20, 3) ("CheckQuickAbort2: NO only little more left\n");
	return 0;
    }
    if ((expectlen - curlen) > (Config.quickAbort.max << 10)) {
	debug(20, 3) ("CheckQuickAbort2: YES too much left to go\n");
	return 1;
    }
    if (expectlen < 100) {
	debug(20, 3) ("CheckQuickAbort2: NO avoid FPE\n");
	return 0;
    }
    if ((curlen / (expectlen / 100)) > (size_t)Config.quickAbort.pct) {
	debug(20, 3) ("CheckQuickAbort2: NO past point of no return\n");
	return 0;
    }
    debug(20, 3) ("CheckQuickAbort2: YES default, returning 1\n");
    return 1;
}

static void
CheckQuickAbort(StoreEntry * entry)
{
    if (entry == NULL)
	return;
    if (storePendingNClients(entry) > 0)
	return;
    if (entry->store_status != STORE_PENDING)
	return;
    if (EBIT_TEST(entry->flags, ENTRY_SPECIAL))
	return;
    if (CheckQuickAbort2(entry) == 0)
	return;
    statCounter.aborted_requests++;
    storeAbort(entry);
}

void
storeClientDumpStats(store_client * thisClient, StoreEntry * output, int clientNumber)
{
    if (thisClient->callback_data == NULL)
	return;
    storeAppendPrintf(output, "\tClient #%d, %p\n", clientNumber, thisClient->callback_data);
    storeAppendPrintf(output, "\t\tcopy_offset: %lu\n",
	(unsigned long) thisClient->copyInto.offset);
    storeAppendPrintf(output, "\t\tcopy_size: %d\n",
	(int) thisClient->copyInto.length);
    storeAppendPrintf(output, "\t\tflags:");
    if (thisClient->flags.disk_io_pending)
	storeAppendPrintf(output, " disk_io_pending");
    if (thisClient->flags.store_copying)
	storeAppendPrintf(output, " store_copying");
    if (thisClient->flags.copy_event_pending)
	storeAppendPrintf(output, " copy_event_pending");
    storeAppendPrintf(output, "\n");

}
