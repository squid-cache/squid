
/*
 * $Id: peer_digest.cc,v 1.1 1998/04/08 22:48:08 rousskov Exp $
 *
 * DEBUG: section 72    Peer Digest Routines
 * AUTHOR: Alex Rousskov
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"

/* local types */

/* local prototypes */
static void peerDigestValidate(peer *p);
static void peerDigestRequest(peer *p);
static void peerDigestFetchReply(void *data, char *buf, ssize_t size);
static void peerDigestRequest(peer *p);
static void peerDigestSwapInHeaders(void *data, char *buf, ssize_t size);
static void peerDigestSwapInCBlock(void *data, char *buf, ssize_t size);
static void peerDigestSwapInMask(void *data, char *buf, ssize_t size);
static int peerDigestFetchedEnough(DigestFetchState *fetch, char *buf, ssize_t size, const char *step_name);
static void peerDigestFetchFinish(DigestFetchState *fetch, char *buf, const char *err_msg);
static int peerDigestSetCBlock(peer *p, const char *buf);
static int peerDigestUpdateMask(peer *peer, int offset, const char *buf, int size);

/* local constants */
#define StoreDigestCBlockSize sizeof(StoreDigestCBlock)

/* min interval for requesting digests from the same peer */
static const time_t PeerDigestRequestMinGap = 1 * 60; /* seconds */

void 
peerDigestInit(peer *p)
{
    assert(p);
    assert(!p->digest.flags);
    assert(!p->digest.cd);
    assert(SM_PAGE_SIZE == 4096); /* we use MEM_4K_BUF */
    if (EBIT_TEST(p->options, NEIGHBOR_NO_DIGEST)) {
	EBIT_SET(p->digest.flags, PD_DISABLED);
    } else {
	cbdataLock(p);
	peerDigestValidate(p);
    }
    EBIT_SET(p->digest.flags, PD_INITED);
}

/* no pending events or requests should exist when you call this */
static void 
peerDigestClean(peer *p)
{
    if (!cbdataValid(p))
	debug(72, 2) ("peerDigest: note: peer %s was reset or deleted\n", p->host);
    debug(72, 2) ("peerDigestClean: disabling peer %s digests for good\n", p->host);
    assert(!EBIT_TEST(p->digest.flags, PD_REQUESTED));
    EBIT_SET(p->digest.flags, PD_DISABLED);
    cbdataUnlock(p);
}

/* request new digest if our copy is too old; schedule next validation */
static void
peerDigestValidate(peer *p)
{
    StoreEntry *e = NULL;
    int do_request;
    time_t req_time = squid_curtime;
    assert(p);
    debug(72, 3) ("peerDigestValidate: digest %s\n", p->host);
    if (!cbdataValid(p)) {
	peerDigestClean(p);
	return;
    }
    debug(72, 3) ("curent time: %s\n", mkrfc1123(squid_curtime));
    if (EBIT_TEST(p->digest.flags, PD_DISABLED))
	return;
    assert(!EBIT_TEST(p->digest.flags, PD_REQUESTED));
    debug(72, 3) ("peerDigestValidate: %s enabled\n", p->host);
    if (p->digest.cd) {
	const cache_key *key;
	key = storeKeyPublic(urlRInternal(p->host, p->http_port, NULL, StoreDigestUrlPath), METHOD_GET);
	e = storeGet(key);
	debug(72, 3) ("peerDigestValidate: %s store entry, key: %s, exp: %s\n", 
	    e ? "has" : "no", storeKeyText(key), mkrfc1123(e ? e->expires : 0));
    }
    /* currently we rely on entry->expire information */
    do_request = !e || e->expires <= squid_curtime;
    req_time = e ? e->expires : squid_curtime;
    if (req_time < squid_curtime)
	req_time = squid_curtime;
    /* do not request too often */
    if (req_time - p->digest.last_req_timestamp < PeerDigestRequestMinGap) {
	if (do_request) {
	    debug(72, 2) ("peerDigestValidate: %s, avoiding too close requests (%d secs).\n", 
		p->host, req_time - p->digest.last_req_timestamp);
	    do_request = 0;
	}
	req_time = p->digest.last_req_timestamp + PeerDigestRequestMinGap;
    }
    /* start request if needed */
    if (do_request) {
	static nest_level = 0;
	nest_level++;
	assert(nest_level  == 1);
	debug(72, 2) ("peerDigestValidate: %s requesting; old e expires: %s\n",
	    p->host, e ? mkrfc1123(e->expires) : "no entry", mkrfc1123(squid_curtime));
	/* will disable digests or call peerDigestValidate() */
	peerDigestRequest(p);
	nest_level--;
	return;
    }
    /* schedule next re-validation */
    eventAdd("peerDigestValidate", (EVH*) peerDigestValidate, 
	p, req_time - squid_curtime);
    debug(72, 2) ("peerDigestValidate: %s scheduled for re-validation at %s\n",
	p->host, mkrfc1123(req_time));
}

/* ask peer cache for a fresh digest */
static void
peerDigestRequest(peer *p)
{
    StoreEntry *e, *old_e;
    char *url;
    const cache_key *key;
    request_t *req;
    DigestFetchState *fetch = NULL;
    assert(p);
    EBIT_SET(p->digest.flags, PD_REQUESTED);
    /* compute future request components */
    url = urlRInternal(p->host, p->http_port, "", StoreDigestUrlPath);
    key = storeKeyPublic(url, METHOD_GET);
    debug(72,2) ("peerDigestRequest: %s key: %s\n", url, storeKeyText(key));
    req = urlParse(METHOD_GET, url);
    assert(req);
    /* add custom headers */
    /* rewrite this when requests get new header interface */
    assert(!req->headers);
    {
	MemBuf mb;
	memBufDefInit(&mb);
	memBufPrintf(&mb, "Accept: %s,text/html\r\n", StoreDigestMimeStr);
	memBufPrintf(&mb, "Cache-control: only-if-cached\r\n");
	memBufAppend(&mb, "\r\n", 2);
	/* kludge! */
	assert(memBufFreeFunc(&mb) == &xfree);
	req->headers = mb.buf;
	req->headers_sz = mb.size;
    }
    /* create fetch state structure */
    fetch = memAllocate(MEM_DIGEST_FETCH_STATE);
    cbdataAdd(fetch, MEM_DIGEST_FETCH_STATE);
    fetch->peer = p;
    fetch->start_time = squid_curtime;
    p->digest.last_req_timestamp = squid_curtime;
    EBIT_SET(req->flags, REQ_CACHABLE);
    assert(EBIT_TEST(req->flags, REQ_CACHABLE)); /* @?@ @?@ */
    /* the rest is based on clientProcessExpired() */
    EBIT_SET(req->flags, REQ_REFRESH);
    old_e = fetch->old_entry = storeGet(key);
    if (old_e) {
	debug(72,5) ("peerDigestRequest: found old entry\n");
	storeLockObject(old_e);
	storeCreateMemObject(old_e, url, url);
	storeClientListAdd(old_e, fetch);
    }
    e = fetch->entry = storeCreateEntry(url, url, req->flags, req->method);
    debug(72,4) ("peerDigestRequest: new entry is private: %d\n",
	(int)EBIT_TEST(e->flag, KEY_PRIVATE));
    storeClientListAdd(e, fetch);
    /* set lastmod to trigger IMS request if possible */
    if (old_e)
	e->lastmod = old_e->lastmod;
    fetch->offset = 0;
    /* push towards peer cache */
    protoDispatch(0, e, req);
    storeClientCopy(e, 0, 0, SM_PAGE_SIZE, memAllocate(MEM_4K_BUF), 
	peerDigestFetchReply, fetch);
}

/* waits for full http headers to be received and parses them */
static void
peerDigestFetchReply(void *data, char *buf, ssize_t size)
{
    DigestFetchState *fetch = data;
    peer *peer = fetch->peer;
    assert(peer && buf);
    assert(!fetch->offset);
    if (peerDigestFetchedEnough(fetch, buf, size, "peerDigestFetchReply"))
	return;
    if (headersEnd(buf, size)) {
	http_status status;
	HttpReply *reply = fetch->entry->mem_obj->reply;
	assert(reply);
	httpReplyParse(reply, buf);
	status = reply->sline.status;
	debug(72, 3) ("peerDigestFetchHeaders: status: %d, expires: %s\n",
	    status, mkrfc1123(reply->expires));
	/* this "if" is based on clientHandleIMSReply() */
	if (status == HTTP_NOT_MODIFIED) {
	    request_t *r = NULL;
	    /* our old entry is fine */
	    assert(fetch->old_entry);
	    if (!fetch->old_entry->mem_obj->request)
		fetch->old_entry->mem_obj->request = r =
		    requestLink(fetch->old_entry->mem_obj->request);
	    httpReplyUpdateOnNotModified(fetch->old_entry->mem_obj->reply, reply);
	    storeTimestampsSet(fetch->old_entry);
	    /* get rid of 304 reply */
	    storeUnregister(fetch->entry, fetch);
	    /* paranoid assert: storeUnregister should not call us recursively */
	    assert(fetch->entry); 
	    storeUnlockObject(fetch->entry);
	    fetch->entry = fetch->old_entry;
	    fetch->old_entry = NULL;
	    requestUnlink(r);
	    fetch->entry->mem_obj->request = NULL;
	} else
	if (status == HTTP_OK) {
	    /* get rid of old entry if any */
	    if (fetch->old_entry) {
		debug(72, 3) ("peerDigestFetchReply: got new digest, requesting release of old digest\n");
		storeUnregister(fetch->old_entry, fetch);
		storeReleaseRequest(fetch->old_entry);
		storeUnlockObject(fetch->old_entry);
		fetch->old_entry = NULL;
	    }
	} else {
	    /* some kind of a bug */
	    peerDigestFetchFinish(fetch, buf, "wrong status code from peer");
	    return;
	}
	/* must have a ready-to-use store entry if we got here */
	/* can we stay with the old digest? */
	if (status == HTTP_NOT_MODIFIED && fetch->peer->digest.cd)
	    peerDigestFetchFinish(fetch, buf, NULL);
	else
	    storeClientCopy(fetch->entry, /* have to swap in */
		0, 0, SM_PAGE_SIZE, buf, peerDigestSwapInHeaders, fetch);
	return;
    } else {
	/* need more data, do we have space? */
	if (size >= SM_PAGE_SIZE)
	    peerDigestFetchFinish(fetch, buf, "too big header");
	else
	    storeClientCopy(fetch->entry, size, 0, SM_PAGE_SIZE, buf,
		peerDigestFetchReply, fetch);
    }
}

/* fetch headers from disk, pass on to SwapInCBlock */
static void
peerDigestSwapInHeaders(void *data, char *buf, ssize_t size)
{
    DigestFetchState *fetch = data;
    peer *peer = fetch->peer;
    size_t hdr_size;
    assert(peer && buf);
    assert(!fetch->offset);
    if (peerDigestFetchedEnough(fetch, buf, size, "peerDigestSwapInHeaders"))
	return;
    if ((hdr_size = headersEnd(buf, size))) {
	assert(fetch->entry->mem_obj->reply);
	if (!fetch->entry->mem_obj->reply->sline.status)
	    httpReplyParse(fetch->entry->mem_obj->reply, buf);
	assert(fetch->entry->mem_obj->reply->sline.status == HTTP_OK);
	fetch->offset += hdr_size;
	storeClientCopy(fetch->entry, size, fetch->offset,
	    SM_PAGE_SIZE, buf,
	    peerDigestSwapInCBlock, fetch);
    } else {
	/* need more data, do we have space? */
	if (size >= SM_PAGE_SIZE)
	    peerDigestFetchFinish(fetch, buf, "too big stored header");
	else
	    storeClientCopy(fetch->entry, size, 0, SM_PAGE_SIZE, buf,
		peerDigestSwapInHeaders, fetch);
    }
}

static void
peerDigestSwapInCBlock(void *data, char *buf, ssize_t size)
{
    DigestFetchState *fetch = data;
    peer *peer = fetch->peer;
    HttpReply *rep = fetch->entry->mem_obj->reply;
    const int seen = fetch->offset + size;
    assert(peer && buf && rep);
    if (peerDigestFetchedEnough(fetch, buf, size, "peerDigestSwapInCBlock"))
	return;
    if (size >= StoreDigestCBlockSize) {
	if (peerDigestSetCBlock(peer, buf)) {
	    fetch->offset += StoreDigestCBlockSize;
	    storeClientCopy(fetch->entry, seen, fetch->offset,
		SM_PAGE_SIZE, buf,
		peerDigestSwapInMask, fetch);
	} else {
	    peerDigestFetchFinish(fetch, buf, "invalid digest cblock");
	}
    } else {
	/* need more data, do we have space? */
	if (size >= SM_PAGE_SIZE)
	    peerDigestFetchFinish(fetch, buf, "too big cblock");
	else
	    storeClientCopy(fetch->entry, size, 0, SM_PAGE_SIZE, buf,
		peerDigestSwapInCBlock, fetch);
    }
}

static void
peerDigestSwapInMask(void *data, char *buf, ssize_t size)
{
    DigestFetchState *fetch = data;
    peer *peer = fetch->peer;
    HttpReply *rep = fetch->entry->mem_obj->reply;
    const int seen = fetch->offset + size;
    assert(peer && buf && rep);
    if (peerDigestFetchedEnough(fetch, buf, size, "peerDigestSwapInCBlock"))
	return;
    if (peerDigestUpdateMask(peer, fetch->mask_offset, buf, size)) {
	fetch->offset += size;
	fetch->mask_offset += size;
	storeClientCopy(fetch->entry, seen, fetch->offset,
	    SM_PAGE_SIZE, buf,
	    peerDigestSwapInMask, fetch);
    } else {
	peerDigestFetchFinish(fetch, buf, "invalid mask");
    }
}

static int
peerDigestFetchedEnough(DigestFetchState *fetch, char *buf, ssize_t size, const char *step_name)
{
    const char *reason = NULL;
    const char *no_bug = NULL;

    debug(72, 3) ("%s: %s offset: %d size: %d.\n",
        step_name, fetch->peer->host, fetch->offset, size);

    /* test exiting conditions */
    if (size < 0) reason = "swap failure";
    else if (!size) reason = no_bug = "eof";
    else if (!fetch->entry) reason = "swap abort(?)";
    else if (fetch->entry->store_status == STORE_ABORTED) reason = "swap abort";
    else if (!cbdataValid(fetch->peer)) reason = "peer disappeard";

    /* report exit reason */
    if (reason) {
	debug(72, 3) ("%s: exiting on %s\n", step_name, reason);
	peerDigestFetchFinish(fetch, buf, no_bug ? NULL : reason);
    }
    return reason != NULL;
}

/* free state structures, disables digest on error */
/* this probably should mimic httpRequestFree() but it does not! @?@ @?@ */
static void
peerDigestFetchFinish(DigestFetchState *fetch, char *buf, const char *err_msg)
{
    peer *peer = fetch->peer;
    MemObject *mem = fetch->entry->mem_obj;
    request_t *req = mem->request;
    const time_t expires = fetch->entry->expires;
    const time_t fetch_resp_time = squid_curtime - fetch->start_time;
    const off_t b_read = (fetch->entry->swap_status == STORE_PENDING) ? mem->inmem_hi : mem->object_sz;
    /* set it here and in peerDigestRequest to protect against long downloads */
    peer->digest.last_req_timestamp = squid_curtime;
    peer->digest.last_fetch_resp_time = fetch_resp_time;
    if (!err_msg && !peer->digest.cd)
	err_msg = "null digest (internal bug?)";
    if (!err_msg && fetch->mask_offset != peer->digest.cd->mask_size)
	err_msg = "premature eof";
    if (fetch->old_entry) {
	debug(72,2) ("peerDigestFetchFinish: deleting old entry\n");
	storeUnregister(fetch->old_entry, fetch);
	storeReleaseRequest(fetch->old_entry);
	storeUnlockObject(fetch->old_entry);
	fetch->old_entry = NULL;
    }
    assert(NULL != fetch->entry);
    if (req) {
	requestUnlink(req);
    }
    if (err_msg) {
	debug(72, 1) ("disabling corrupted (%s) digest from %s\n",
	    err_msg, peer->host);
	if (peer->digest.cd) {
	    cacheDigestDestroy(peer->digest.cd);
	    peer->digest.cd = NULL;
	}
	EBIT_SET(peer->digest.flags, PD_DISABLED);
	EBIT_CLR(peer->digest.flags, PD_USABLE);
	/* release buggy entry */
	storeReleaseRequest(fetch->entry);
    } else {
        storeComplete(fetch->entry);
	EBIT_SET(peer->digest.flags, PD_USABLE);
    }
    storeUnregister(fetch->entry, fetch);
    storeUnlockObject(fetch->entry);
    fetch->entry = NULL;
    cbdataFree(fetch);
    fetch = NULL;
    memFree(MEM_4K_BUF, buf);
    EBIT_CLR(peer->digest.flags, PD_REQUESTED);
    kb_incr(&Counter.cd.kbytes_recv, (size_t)b_read);
    Counter.cd.times_used++;
    debug(72, 2) ("peerDigestFetchFinish: %s  took: %d secs; expires: %s\n",
	peer->host, fetch_resp_time, mkrfc1123(expires));
    /* schedule next check */
    peerDigestValidate(peer);
    /* paranoid loop detection */
    assert(!EBIT_TEST(peer->digest.flags, PD_REQUESTED));
    debug(72, 3) ("peerDigestFetchFinish: %s done\n", peer->host);
}

static int
peerDigestSetCBlock(peer *peer, const char *buf)
{
    StoreDigestCBlock cblock;
    int freed_size = 0;
    xmemcpy(&cblock, buf, sizeof(cblock));
    /* network -> host conversions */
    cblock.ver.current = ntohs(cblock.ver.current);
    cblock.ver.required = ntohs(cblock.ver.required);
    cblock.capacity = ntohl(cblock.capacity);
    cblock.count = ntohl(cblock.count);
    cblock.del_count = ntohl(cblock.del_count);
    cblock.mask_size = ntohl(cblock.mask_size);
    debug(72,2) ("got digest cblock from %s; ver: %d (req: %d)\n",
	peer->host, (int)cblock.ver.current, (int)cblock.ver.required);
    debug(72,2) ("\t size: %d bytes, e-cnt: %d, e-util: %d%%\n",
	cblock.mask_size, cblock.count,
	xpercentInt(cblock.count, cblock.capacity));
    /* check version requirements */
    if (cblock.ver.required > CacheDigestVer.current) {
	debug(72,1) ("%s digest requires version %d; have: %d\n",
	    peer->host, cblock.ver.required, CacheDigestVer.current);
	return 0;
    }
    /* check consistency */
    if (cblock.ver.required > cblock.ver.current || 
	cblock.mask_size <= 0 || cblock.capacity <= 0) {
	debug(72,0) ("%s digest cblock is corrupted.\n", peer->host);
	return 0;
    }
    /*
     * no cblock bugs below this point
     */
    /* check size changes */
    if (peer->digest.cd && cblock.mask_size != peer->digest.cd->mask_size) {
	debug(72,2) ("%s digest changed size: %d -> %d\n",
	    peer->host, cblock.mask_size, peer->digest.cd->mask_size);
	freed_size = peer->digest.cd->mask_size;
	cacheDigestDestroy(peer->digest.cd);
	peer->digest.cd = NULL;
    }
    if (!peer->digest.cd) {
	debug(72,2) ("cloning %s digest; size: %d (%+d) bytes\n",
	    peer->host, cblock.mask_size, (int) (cblock.mask_size - freed_size));
	peer->digest.cd = cacheDigestSizedCreate(cblock.mask_size, cblock.capacity);
	if (cblock.mask_size >= freed_size)
	    kb_incr(&Counter.cd.memory, cblock.mask_size - freed_size);
    }
    /* these assignments leave us in an inconsistent state until we finish reading the digest */
    peer->digest.cd->count = cblock.count;
    peer->digest.cd->del_count = cblock.del_count;
    return 1;
}

/* updates current mask. checks for overflows */
static int
peerDigestUpdateMask(peer *peer, int offset, const char *buf, int size)
{
    if (size) {
	assert(offset >= 0);
	assert(peer->digest.cd);
	if (offset + size > peer->digest.cd->mask_size) {
	    debug(72,0) ("peerDigestUpdateMask: %s digest is larger than expected: %d > %d\n",
		peer->host, offset + size, peer->digest.cd->mask_size);
	    return 0;
	}
	xmemcpy(peer->digest.cd->mask + offset, buf, size);
    }
    return 1;
}
		
