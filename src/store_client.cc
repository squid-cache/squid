
/*
 * $Id: store_client.cc,v 1.74 1999/07/13 14:51:23 wessels Exp $
 *
 * DEBUG: section 20    Storage Manager Client-Side Interface
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

/*
 * NOTE: 'Header' refers to the swapfile metadata header.
 *       'Body' refers to the swapfile body, which is the full
 *        HTTP reply (including HTTP headers and body).
 */
static STRCB storeClientReadBody;
static STRCB storeClientReadHeader;
static void storeClientCopy2(StoreEntry * e, store_client * sc);
static void storeClientFileRead(store_client * sc);
static EVH storeClientCopyEvent;
static store_client_t storeClientType(StoreEntry *);
static int CheckQuickAbort2(StoreEntry * entry);
static void CheckQuickAbort(StoreEntry * entry);

/* check if there is any client waiting for this object at all */
/* return 1 if there is at least one client */
int
storeClientWaiting(const StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    store_client *sc;
    for (sc = mem->clients; sc; sc = sc->next) {
	if (sc->callback_data != NULL)
	    return 1;
    }
    return 0;
}

store_client *
storeClientListSearch(const MemObject * mem, void *data)
{
    store_client *sc;
    for (sc = mem->clients; sc; sc = sc->next) {
	if (sc->callback_data == data)
	    break;
    }
    return sc;
}

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
     * otherwise, make subsequent clients read from disk so they
     * can not delay the first, and vice-versa.
     */
    else
	return STORE_DISK_CLIENT;
}

/* add client with fd to client list */
void
storeClientListAdd(StoreEntry * e, void *data)
{
    MemObject *mem = e->mem_obj;
    store_client **T;
    store_client *sc;
    assert(mem);
    if (storeClientListSearch(mem, data) != NULL)
	return;
    mem->nclients++;
    sc = memAllocate(MEM_STORE_CLIENT);
    cbdataAdd(sc, memFree, MEM_STORE_CLIENT);	/* sc is callback_data for file_read */
    sc->callback_data = data;
    sc->seen_offset = 0;
    sc->copy_offset = 0;
    sc->flags.disk_io_pending = 0;
    sc->entry = e;
    sc->type = storeClientType(e);
    if (sc->type == STORE_DISK_CLIENT)
	/* assert we'll be able to get the data we want */
	/* maybe we should open swapin_fd here */
	assert(e->swap_file_number > -1 || storeSwapOutAble(e));
    for (T = &mem->clients; *T; T = &(*T)->next);
    *T = sc;
#if DELAY_POOLS
    sc->delay_id = 0;
#endif
}

static void
storeClientCopyEvent(void *data)
{
    store_client *sc = data;
    debug(20, 3) ("storeClientCopyEvent: Running\n");
    sc->flags.copy_event_pending = 0;
    if (!sc->callback)
	return;
    storeClientCopy2(sc->entry, sc);
}

/* copy bytes requested by the client */
void
storeClientCopy(StoreEntry * e,
    off_t seen_offset,
    off_t copy_offset,
    size_t size,
    char *buf,
    STCB * callback,
    void *data)
{
    store_client *sc;
    assert(!EBIT_TEST(e->flags, ENTRY_ABORTED));
    debug(20, 3) ("storeClientCopy: %s, seen %d, want %d, size %d, cb %p, cbdata %p\n",
	storeKeyText(e->key),
	(int) seen_offset,
	(int) copy_offset,
	(int) size,
	callback,
	data);
    sc = storeClientListSearch(e->mem_obj, data);
    assert(sc != NULL);
    assert(sc->callback == NULL);
    sc->copy_offset = copy_offset;
    sc->seen_offset = seen_offset;
    sc->callback = callback;
    sc->copy_buf = buf;
    sc->copy_size = size;
    sc->copy_offset = copy_offset;
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
    if (sc->copy_offset < len)
	return 0;
    return 1;
}

static void
storeClientCopy2(StoreEntry * e, store_client * sc)
{
    STCB *callback = sc->callback;
    MemObject *mem = e->mem_obj;
    size_t sz;
    if (sc->flags.copy_event_pending)
	return;
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
    cbdataLock(sc);		/* ick, prevent sc from getting freed */
    sc->flags.store_copying = 1;
    debug(20, 3) ("storeClientCopy2: %s\n", storeKeyText(e->key));
    assert(callback != NULL);
    /*
     * We used to check for ENTRY_ABORTED here.  But there were some
     * problems.  For example, we might have a slow client (or two) and
     * the server-side is reading far ahead and swapping to disk.  Even
     * if the server-side aborts, we want to give the client(s)
     * everything we got before the abort condition occurred.
     */
    if (storeClientNoMoreToSend(e, sc)) {
	/* There is no more to send! */
	sc->flags.disk_io_pending = 0;
	sc->callback = NULL;
	callback(sc->callback_data, sc->copy_buf, 0);
    } else if (e->store_status == STORE_PENDING && sc->seen_offset >= mem->inmem_hi) {
	/* client has already seen this, wait for more */
	debug(20, 3) ("storeClientCopy2: Waiting for more\n");
    } else if (sc->copy_offset >= mem->inmem_lo && sc->copy_offset < mem->inmem_hi) {
	/* What the client wants is in memory */
	debug(20, 3) ("storeClientCopy2: Copying from memory\n");
	sz = stmemCopy(&mem->data_hdr, sc->copy_offset, sc->copy_buf, sc->copy_size);
	sc->flags.disk_io_pending = 0;
	sc->callback = NULL;
	callback(sc->callback_data, sc->copy_buf, sz);
    } else if (sc->swapin_sio == NULL) {
	debug(20, 3) ("storeClientCopy2: Need to open swap in file\n");
	assert(sc->type == STORE_DISK_CLIENT);
	/* gotta open the swapin file */
	if (storeTooManyDiskFilesOpen()) {
	    /* yuck -- this causes a TCP_SWAPFAIL_MISS on the client side */
	    sc->callback = NULL;
	    callback(sc->callback_data, sc->copy_buf, -1);
	} else if (!sc->flags.disk_io_pending) {
	    sc->flags.disk_io_pending = 1;
	    sc->swapin_sio = storeSwapInStart(e);
	    if (NULL == sc->swapin_sio) {
		sc->flags.disk_io_pending = 0;
		sc->callback = NULL;
		callback(sc->callback_data, sc->copy_buf, -1);
	    } else {
		storeClientFileRead(sc);
	    }
	} else {
	    debug(20, 2) ("storeClientCopy2: Averted multiple fd operation\n");
	}
    } else {
	debug(20, 3) ("storeClientCopy: reading from STORE\n");
	assert(sc->type == STORE_DISK_CLIENT);
	if (!sc->flags.disk_io_pending) {
	    sc->flags.disk_io_pending = 1;
	    storeClientFileRead(sc);
	} else {
	    debug(20, 2) ("storeClientCopy2: Averted multiple fd operation\n");
	}
    }
    sc->flags.store_copying = 0;
    cbdataUnlock(sc);		/* ick, allow sc to be freed */
}

static void
storeClientFileRead(store_client * sc)
{
    MemObject *mem = sc->entry->mem_obj;
    assert(sc->callback != NULL);
    if (mem->swap_hdr_sz == 0) {
	storeRead(sc->swapin_sio,
	    sc->copy_buf,
	    sc->copy_size,
	    0,
	    storeClientReadHeader,
	    sc);
    } else {
	if (sc->entry->swap_status == SWAPOUT_WRITING)
	    assert(storeOffset(mem->swapout.sio) > sc->copy_offset + mem->swap_hdr_sz);
	storeRead(sc->swapin_sio,
	    sc->copy_buf,
	    sc->copy_size,
	    sc->copy_offset + mem->swap_hdr_sz,
	    storeClientReadBody,
	    sc);
    }
}

static void
storeClientReadBody(void *data, const char *buf, ssize_t len)
{
    store_client *sc = data;
    MemObject *mem = sc->entry->mem_obj;
    STCB *callback = sc->callback;
    assert(sc->flags.disk_io_pending);
    sc->flags.disk_io_pending = 0;
    assert(sc->callback != NULL);
    debug(20, 3) ("storeClientReadBody: len %d\n", len);
    if (sc->copy_offset == 0 && len > 0 && mem->reply->sline.status == 0)
	httpReplyParse(mem->reply, sc->copy_buf);
    sc->callback = NULL;
    callback(sc->callback_data, sc->copy_buf, len);
}

static void
storeClientReadHeader(void *data, const char *buf, ssize_t len)
{
    store_client *sc = data;
    StoreEntry *e = sc->entry;
    MemObject *mem = e->mem_obj;
    STCB *callback = sc->callback;
    int swap_hdr_sz = 0;
    size_t body_sz;
    size_t copy_sz;
    tlv *tlv_list;
    assert(sc->flags.disk_io_pending);
    sc->flags.disk_io_pending = 0;
    assert(sc->callback != NULL);
    debug(20, 3) ("storeClientReadHeader: len %d\n", len);
    if (len < 0) {
	debug(20, 3) ("storeClientReadHeader: %s\n", xstrerror());
	sc->callback = NULL;
	callback(sc->callback_data, sc->copy_buf, len);
	return;
    }
    tlv_list = storeSwapMetaUnpack(buf, &swap_hdr_sz);
    if (tlv_list == NULL) {
	debug(20, 1) ("storeClientReadHeader: failed to unpack meta data\n");
	sc->callback = NULL;
	callback(sc->callback_data, sc->copy_buf, -1);
	return;
    }
    /*
     * XXX Here we should check the meta data and make sure we got
     * the right object.
     */
    storeSwapTLVFree(tlv_list);
    mem->swap_hdr_sz = swap_hdr_sz;
    mem->object_sz = e->swap_file_sz - swap_hdr_sz;
    /*
     * If our last read got some data the client wants, then give
     * it to them, otherwise schedule another read.
     */
    body_sz = len - swap_hdr_sz;
    if (sc->copy_offset < body_sz) {
	/*
	 * we have (part of) what they want
	 */
	copy_sz = XMIN(sc->copy_size, body_sz);
	debug(20, 3) ("storeClientReadHeader: copying %d bytes of body\n",
	    copy_sz);
	xmemmove(sc->copy_buf, sc->copy_buf + swap_hdr_sz, copy_sz);
	if (sc->copy_offset == 0 && len > 0 && mem->reply->sline.status == 0)
	    httpReplyParse(mem->reply, sc->copy_buf);
	sc->callback = NULL;
	callback(sc->callback_data, sc->copy_buf, copy_sz);
	return;
    }
    /*
     * we don't have what the client wants, but at least we now
     * know the swap header size.
     */
    storeClientFileRead(sc);
}

int
storeClientCopyPending(StoreEntry * e, void *data)
{
    /* return 1 if there is a callback registered for this client */
    store_client *sc = storeClientListSearch(e->mem_obj, data);
    if (sc == NULL)
	return 0;
    if (sc->callback == NULL)
	return 0;
    return 1;
}

int
storeUnregister(StoreEntry * e, void *data)
{
    MemObject *mem = e->mem_obj;
    store_client *sc;
    store_client **S;
    STCB *callback;
    if (mem == NULL)
	return 0;
    debug(20, 3) ("storeUnregister: called for '%s'\n", storeKeyText(e->key));
    for (S = &mem->clients; (sc = *S) != NULL; S = &(*S)->next) {
	if (sc->callback_data == data)
	    break;
    }
    if (sc == NULL)
	return 0;
    if (sc == mem->clients) {
	/*
	 * If we are unregistering the _first_ client for this
	 * entry, then we have to reset the client FD to -1.
	 */
	mem->fd = -1;
    }
    *S = sc->next;
    mem->nclients--;
    sc->flags.disk_io_pending = 0;
    if (e->store_status == STORE_OK && e->swap_status != SWAPOUT_DONE)
	storeSwapOut(e);
    if (sc->swapin_sio) {
	storeClose(sc->swapin_sio);
	sc->swapin_sio = NULL;
    }
    if ((callback = sc->callback) != NULL) {
	/* callback with ssize = -1 to indicate unexpected termination */
	debug(20, 3) ("storeUnregister: store_client for %s has a callback\n",
	    mem->url);
	sc->callback = NULL;
	callback(sc->callback_data, sc->copy_buf, -1);
    }
#if DELAY_POOLS
    delayUnregisterDelayIdPtr(&sc->delay_id);
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
    off_t lowest = mem->inmem_hi;
    store_client *sc;
    store_client *nx = NULL;
    for (sc = mem->clients; sc; sc = nx) {
	nx = sc->next;
	if (sc->callback_data == NULL)	/* open slot */
	    continue;
	if (sc->type != STORE_MEM_CLIENT)
	    continue;
	if (sc->copy_offset < lowest)
	    lowest = sc->copy_offset;
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
    store_client *nx = NULL;
    assert(mem->clients != NULL || mem->nclients == 0);
    debug(20, 3) ("InvokeHandlers: %s\n", storeKeyText(e->key));
    /* walk the entire list looking for valid callbacks */
    for (sc = mem->clients; sc; sc = nx) {
	nx = sc->next;
	debug(20, 3) ("InvokeHandlers: checking client #%d\n", i++);
	if (sc->callback_data == NULL)
	    continue;
	if (sc->callback == NULL)
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
    int curlen;
    int minlen;
    int expectlen;
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
    curlen = (int) mem->inmem_hi;
    minlen = (int) Config.quickAbort.min << 10;
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
    if ((curlen / (expectlen / 100)) > Config.quickAbort.pct) {
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
    Counter.aborted_requests++;
    storeAbort(entry);
}
