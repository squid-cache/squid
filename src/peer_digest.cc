
/*
 * $Id: peer_digest.cc,v 1.49 1998/09/14 21:58:52 wessels Exp $
 *
 * DEBUG: section 72    Peer Digest Routines
 * AUTHOR: Alex Rousskov
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

#if USE_CACHE_DIGESTS

/* local types */

/* local prototypes */
static void peerDigestClean(peer * p);
static time_t peerDigestNextDisDelay(const peer * p);
static time_t peerDigestExpiresDelay(const peer * p, const StoreEntry * e);
static void peerDigestDisable(peer * p);
static void peerDigestDelay(peer * p, int disable, time_t delay);
static EVH peerDigestValidate;
static void peerDigestRequest(peer * p);
static void peerDigestFetchReply(void *data, char *buf, ssize_t size);
static void peerDigestRequest(peer * p);
static void peerDigestSwapInHeaders(void *data, char *buf, ssize_t size);
static void peerDigestSwapInCBlock(void *data, char *buf, ssize_t size);
static STCB peerDigestSwapInMask;
static int peerDigestFetchedEnough(DigestFetchState * fetch, char *buf, ssize_t size, const char *step_name);
static void peerDigestFetchFinish(DigestFetchState * fetch, char *buf, const char *err_msg);
static int peerDigestSetCBlock(peer * p, const char *buf);
static int peerDigestUseful(const peer * peer);
#define max_delay(t1,t2) ((t1) >= (t2) ? (t1) : (t2))


/* local constants */
#define StoreDigestCBlockSize sizeof(StoreDigestCBlock)

/* min interval for requesting digests from the same peer */
static const time_t PeerDigestRequestMinGap = 5 * 60;	/* seconds */
/* min interval for requesting digests at start */
static const time_t GlobalDigestRequestMinGap = 1 * 60;		/* seconds */

/* local vars */
static time_t global_last_req_timestamp = 0;

void
peerDigestInit(void *data)
{
    peer *p = data;
    assert(p);
    assert(p->digest.flags == (1 << PD_INIT_PENDING));
    assert(!p->digest.cd);
    assert(SM_PAGE_SIZE == 4096);	/* we use MEM_4K_BUF */
    if (p->options.no_digest) {
	peerDigestDisable(p);
    } else {
	cbdataLock(p);
	peerDigestValidate(p);
    }
    EBIT_SET(p->digest.flags, PD_INITED);
    EBIT_CLR(p->digest.flags, PD_INIT_PENDING);
}

/* no pending events or requests should exist when you call this */
static void
peerDigestClean(peer * p)
{
    if (!cbdataValid(p))
	debug(72, 2) ("peerDigest: note: peer '%s' was reset or deleted\n",
	    p->host ? p->host : "<null>");
    assert(!EBIT_TEST(p->digest.flags, PD_REQUESTED));
    peerDigestDisable(p);
    cbdataUnlock(p);
}

/* disables peer for good */
static void
peerDigestDisable(peer * p)
{
    peerDigestDelay(p, 1, -1);
}

/* next delay for a disabled entry */
static time_t
peerDigestNextDisDelay(const peer * p)
{
    assert(p);
    return p->digest.last_dis_delay ?
	2 * p->digest.last_dis_delay :	/* exponential backoff */
	PeerDigestRequestMinGap;	/* minimal delay */
}

/* artificially increases expires to avoid race conditions */
static time_t
peerDigestExpiresDelay(const peer * p, const StoreEntry * e)
{
    assert(p);
    if (!e)
	return 0;
    if (e->expires > 0)
	return e->expires + PeerDigestRequestMinGap - squid_curtime;
    return PeerDigestRequestMinGap;
}


/* delays/disables digest for a psecified delay (disables forever if negative delay) */
static void
peerDigestDelay(peer * p, int disable, time_t delay)
{
    assert(p);
    if (disable) {
	EBIT_SET(p->digest.flags, PD_DISABLED);
	p->digest.last_dis_delay = delay;
    }
    if (delay >= 0) {
	assert(delay || !disable);
	debug(72, 2) ("peerDigestDelay: %s: peer %s for %d secs till %s\n",
	    disable ? "disabling" : "delaying",
	    p->host ? p->host : "<null>",
	    delay, mkrfc1123(squid_curtime + delay));
	eventAdd("peerDigestValidate", peerDigestValidate, p, (double) delay, 1);
    } else {
	assert(disable);
	debug(72, 2) ("peerDigestDisable: disabling peer %s for good\n",
	    p->host ? p->host : "<null>");
	/* just in case, will not need it anymore */
	EBIT_CLR(p->digest.flags, PD_USABLE);
    }
}

/* request new digest if our copy is too old; schedule next validation */
static void
peerDigestValidate(void *data)
{
    peer *p = data;
    StoreEntry *e = NULL;
    int do_request;
    time_t req_time = squid_curtime;
    assert(p);
    debug(72, 3) ("peerDigestValidate: digest %s\n", p->host);
    if (!cbdataValid(p)) {
	peerDigestClean(p);
	return;
    }
    debug(72, 3) ("current GMT time: %s\n", mkrfc1123(squid_curtime));
    assert(!EBIT_TEST(p->digest.flags, PD_REQUESTED));
    debug(72, 3) ("peerDigestValidate: %s was %s disabled\n",
	p->host, p->digest.last_dis_delay ? "" : "not");
    if (1 /* p->digest.cd */ ) {
	const cache_key *key;
	const char *u = internalRemoteUri(p->host, p->http_port, "/squid-internal-periodic/", StoreDigestUrlPath);
	key = storeKeyPublic(u, METHOD_GET);
	e = storeGet(key);
	debug(72, 3) ("peerDigestValidate: %s store entry, key: %s, exp: %s\n",
	    e ? "has" : "no", storeKeyText(key), mkrfc1123(e ? e->expires : 0));
    }
    /* currently we rely on entry->expire information */
    {
	const int loaded = p->digest.cd != NULL;
	const time_t exp_delay = loaded ? peerDigestExpiresDelay(p, e) : 0;
	do_request = exp_delay <= 0;
	req_time = squid_curtime + exp_delay;
	if (req_time < squid_curtime)
	    req_time = squid_curtime;
    }
    /* do not request too often from one peer */
    if (req_time - p->digest.last_req_timestamp < PeerDigestRequestMinGap) {
	if (do_request) {
	    debug(72, 2) ("peerDigestValidate: %s, avoiding too close peer requests (%d secs).\n",
		p->host, req_time - p->digest.last_req_timestamp);
	    do_request = 0;
	}
	req_time = p->digest.last_req_timestamp + PeerDigestRequestMinGap;
    }
    /* at start, do not request too often from all peers */
    if (!EBIT_TEST(p->digest.flags, PD_INITED) &&
	req_time - global_last_req_timestamp < GlobalDigestRequestMinGap) {
	if (do_request) {
	    debug(72, 2) ("peerDigestValidate: %s, avoiding too close requests (%d secs).\n",
		p->host, req_time - global_last_req_timestamp);
	    do_request = 0;
	}
	req_time = global_last_req_timestamp + GlobalDigestRequestMinGap;
	/* otherwise we have all but one peer returning at the same moment @?@ */
	debug(72, 5) ("peerDigestValidate: inc req_time (%+d) in anticipation of more reqs\n",
	    (int) (req_time - global_last_req_timestamp));
	global_last_req_timestamp = req_time;
    }
    /* start request if needed */
    if (do_request) {
	static int nest_level = 0;
	nest_level++;
	assert(nest_level == 1);
	debug(72, 2) ("peerDigestValidate: %s requesting; old entry expires: %s\n",
	    p->host, e ? mkrfc1123(e->expires) : "no entry");
	/* will eventually disable digests or call peerDigest Delay */
	peerDigestRequest(p);
	nest_level--;
    } else {
	/* schedule next re-validation */
	assert(req_time > squid_curtime);
	peerDigestDelay(p, !p->digest.cd, req_time - squid_curtime);
    }
}

/* ask peer cache for a fresh digest */
static void
peerDigestRequest(peer * p)
{
    StoreEntry *e, *old_e;
    char *url;
    const cache_key *key;
    request_t *req;
    DigestFetchState *fetch = NULL;
    assert(p);
    EBIT_SET(p->digest.flags, PD_REQUESTED);
    /* compute future request components */
    url = internalRemoteUri(p->host, p->http_port, "/squid-internal-periodic/", StoreDigestUrlPath);
    key = storeKeyPublic(url, METHOD_GET);
    debug(72, 2) ("peerDigestRequest: %s key: %s\n", url, storeKeyText(key));
    req = urlParse(METHOD_GET, url);
    if (NULL == req) {
	debug(72, 1) ("peerDigestRequest: Bad URI: %s\n", url);
	return;			/* @?@ */
    }
    /* add custom headers */
    assert(!req->header.len);
    httpHeaderPutStr(&req->header, HDR_ACCEPT, StoreDigestMimeStr);
    httpHeaderPutStr(&req->header, HDR_ACCEPT, "text/html");
    /* create fetch state structure */
    fetch = memAllocate(MEM_DIGEST_FETCH_STATE);
    cbdataAdd(fetch, MEM_DIGEST_FETCH_STATE);
    fetch->request = requestLink(req);
    fetch->peer = p;
    fetch->start_time = squid_curtime;
    p->digest.last_req_timestamp = squid_curtime;
    global_last_req_timestamp = squid_curtime;
    req->flags.cachable = 1;
    /* the rest is based on clientProcessExpired() */
    req->flags.refresh = 1;
    old_e = fetch->old_entry = storeGet(key);
    if (old_e) {
	debug(72, 5) ("peerDigestRequest: found old entry\n");
	storeLockObject(old_e);
	storeCreateMemObject(old_e, url, url);
	storeClientListAdd(old_e, fetch);
    }
    e = fetch->entry = storeCreateEntry(url, url, req->flags, req->method);
    debug(72, 5) ("peerDigestRequest: new entry is private: %d\n",
	(int) e->flags.key_private);
    storeClientListAdd(e, fetch);
    /* set lastmod to trigger IMS request if possible */
    if (old_e)
	e->lastmod = old_e->lastmod;
    fetch->offset = 0;
    debug(72, 3) ("peerDigestRequest: forwarding to fwdStart...\n");
    /* push towards peer cache */
    fwdStart(-1, e, req, no_addr);
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
	debug(72, 3) ("peerDigestFetchReply: %s status: %d, expires: %s\n",
	    peer->host, status, mkrfc1123(reply->expires));
	/* this "if" is based on clientHandleIMSReply() */
	if (status == HTTP_NOT_MODIFIED) {
	    request_t *r = NULL;
	    /* our old entry is fine */
	    assert(fetch->old_entry);
	    if (!fetch->old_entry->mem_obj->request)
		fetch->old_entry->mem_obj->request = r =
		    requestLink(fetch->entry->mem_obj->request);
	    assert(fetch->old_entry->mem_obj->request);
	    httpReplyUpdateOnNotModified(fetch->old_entry->mem_obj->reply, reply);
	    storeTimestampsSet(fetch->old_entry);
	    /* get rid of 304 reply */
	    storeUnregister(fetch->entry, fetch);
	    /* paranoid assert: storeUnregister should not call us recursively */
	    assert(fetch->entry);
	    storeUnlockObject(fetch->entry);
	    fetch->entry = fetch->old_entry;
	    fetch->old_entry = NULL;
	    /* preserve request -- we need its size to update counters */
	    /* requestUnlink(r); */
	    /* fetch->entry->mem_obj->request = NULL; */
	    assert(fetch->entry->mem_obj);
	} else if (status == HTTP_OK) {
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
	    peerDigestFetchFinish(fetch, buf, httpStatusLineReason(&reply->sline));
	    return;
	}
	/* must have a ready-to-use store entry if we got here */
	/* can we stay with the old digest? */
	if (status == HTTP_NOT_MODIFIED && fetch->peer->digest.cd)
	    peerDigestFetchFinish(fetch, buf, NULL);
	else
	    storeClientCopy(fetch->entry,	/* have to swap in */
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
	if (fetch->entry->mem_obj->reply->sline.status != HTTP_OK) {
	    debug(72, 1) ("peerDigestSwapInHeaders: %s status %d got cached!\n",
		peer->host, fetch->entry->mem_obj->reply->sline.status);
	    peerDigestFetchFinish(fetch, buf, "internal status error");
	    return;
	}
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
	    /* switch to CD buffer */
	    memFree(MEM_4K_BUF, buf);
	    buf = NULL;
	    assert(peer->digest.cd->mask);
	    storeClientCopy(fetch->entry,
		seen,
		fetch->offset,
		peer->digest.cd->mask_size,
		peer->digest.cd->mask,
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
    size_t buf_sz;
    assert(peer && buf && rep);
    assert(peer->digest.cd && peer->digest.cd->mask);
    /*
     * NOTE! buf points to the middle of peer->digest.cd->mask!
     */
    if (peerDigestFetchedEnough(fetch, NULL, size, "peerDigestSwapInMask"))
	return;
    fetch->offset += size;
    fetch->mask_offset += size;
    if (fetch->mask_offset >= peer->digest.cd->mask_size) {
	debug(72, 2) ("peerDigestSwapInMask: Done! Got %d, expected %d\n",
	    fetch->mask_offset, peer->digest.cd->mask_size);
	assert(fetch->mask_offset == peer->digest.cd->mask_size);
	peerDigestFetchFinish(fetch, NULL, NULL);
	return;
    }
    buf_sz = peer->digest.cd->mask_size - fetch->mask_offset;
    assert(buf_sz > 0);
    storeClientCopy(fetch->entry,
	fetch->offset,
	fetch->offset,
	buf_sz,
	peer->digest.cd->mask + fetch->mask_offset,
	peerDigestSwapInMask, fetch);
}

static int
peerDigestFetchedEnough(DigestFetchState * fetch, char *buf, ssize_t size, const char *step_name)
{
    const char *reason = NULL;
    const char *no_bug = NULL;

    debug(72, 6) ("%s: %s offset: %d size: %d.\n",
	step_name, fetch->peer->host, fetch->offset, size);

    /* test exiting conditions */
    if (size < 0)
	reason = "swap failure";
    else if (!size)
	reason = no_bug = "eof";
    else if (!fetch->entry)
	reason = "swap abort(?)";
    else if (fetch->entry->store_status == STORE_ABORTED)
	reason = "swap abort";
    else if (!cbdataValid(fetch->peer))
	reason = "peer disappeared";

    /* report exit reason */
    if (reason) {
	debug(72, 3) ("%s: exiting on %s\n", step_name, reason);
	peerDigestFetchFinish(fetch, buf, no_bug ? NULL : reason);
    }
    return reason != NULL;
}

/* free state structures, disables digest on error */
static void
peerDigestFetchFinish(DigestFetchState * fetch, char *buf, const char *err_msg)
{
    peer *peer = fetch->peer;
    MemObject *mem = fetch->entry->mem_obj;
    const time_t expires = fetch->entry->expires;
    const time_t fetch_resp_time = squid_curtime - fetch->start_time;
    const int b_read = (fetch->entry->store_status == STORE_PENDING) ?
    mem->inmem_hi : mem->object_sz;
    const int req_len = fetch->request ? httpRequestPrefixLen(fetch->request) : 0;
    assert(fetch->request);
    /* final checks */
    if (!err_msg) {
	if (!peer->digest.cd)
	    err_msg = "null digest (internal bug?)";
	else if (fetch->mask_offset != peer->digest.cd->mask_size)
	    err_msg = "premature eof";
	else if (!peerDigestUseful(peer))
	    err_msg = "useless digest";
    }
    if (fetch->old_entry) {
	debug(72, 2) ("peerDigestFetchFinish: deleting old entry\n");
	storeUnregister(fetch->old_entry, fetch);
	storeReleaseRequest(fetch->old_entry);
	storeUnlockObject(fetch->old_entry);
	fetch->old_entry = NULL;
    }
    assert(fetch->entry);
    debug(72, 3) ("peerDigestFetchFinish: %s, read %d b, expires: %s lmt: %s\n",
	peer->host, b_read,
	mkrfc1123(fetch->entry->expires), mkrfc1123(fetch->entry->lastmod));
    if (err_msg) {
	if (cbdataValid(peer))
	    debug(72, 1) ("disabling corrupted (%s) digest from %s\n",
	        err_msg, peer->host);
	if (peer->digest.cd) {
	    cacheDigestDestroy(peer->digest.cd);
	    peer->digest.cd = NULL;
	}
	/* disable for a while */
	EBIT_CLR(peer->digest.flags, PD_USABLE);
	peerDigestDelay(peer, 1,
	    max_delay(
		peerDigestExpiresDelay(peer, fetch->entry),
		peerDigestNextDisDelay(peer)));
	/* release buggy entry */
	storeReleaseRequest(fetch->entry);
    } else {
	/* ugly condition, but how? */
	if (fetch->entry->store_status == STORE_OK) {
	    debug(72, 2) ("re-used old digest from %s\n", peer->host);
	} else {
	    debug(72, 2) ("received valid digest from %s\n", peer->host);
	}
	EBIT_SET(peer->digest.flags, PD_USABLE);
	EBIT_CLR(peer->digest.flags, PD_DISABLED);
	peer->digest.last_dis_delay = 0;
	peerDigestDelay(peer, 0,
	    max_delay(peerDigestExpiresDelay(peer, fetch->entry), 0));
    }
    /* update global stats */
    /* note: outgoing numbers are not precise! @?@ */
    kb_incr(&Counter.cd.kbytes_sent, req_len);
    kb_incr(&Counter.cd.kbytes_recv, (size_t) b_read);
    Counter.cd.msgs_sent++;
    Counter.cd.msgs_recv++;
    /* update peer stats */
    kb_incr(&peer->digest.stats.kbytes_sent, req_len);
    kb_incr(&peer->digest.stats.kbytes_recv, (size_t) b_read);
    peer->digest.stats.msgs_sent++;
    peer->digest.stats.msgs_recv++;
    /* unlock everything */
    storeUnregister(fetch->entry, fetch);
    storeUnlockObject(fetch->entry);
    requestUnlink(fetch->request);
    fetch->entry = NULL;
    fetch->request = NULL;
    cbdataFree(fetch);
    fetch = NULL;
    if (buf)
	memFree(MEM_4K_BUF, buf);
    buf = NULL;
    /* set it here and in peerDigestRequest to protect against long downloads */
    peer->digest.last_req_timestamp = squid_curtime;
    peer->digest.last_fetch_resp_time = fetch_resp_time;
    EBIT_CLR(peer->digest.flags, PD_REQUESTED);
    debug(72, 2) ("peerDigestFetchFinish: %s done; took: %d secs; expires: %s\n",
	peer->host, fetch_resp_time, mkrfc1123(expires));
}

static int
peerDigestSetCBlock(peer * peer, const char *buf)
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
    debug(72, 2) ("got digest cblock from %s; ver: %d (req: %d)\n",
	peer->host, (int) cblock.ver.current, (int) cblock.ver.required);
    debug(72, 2) ("\t size: %d bytes, e-cnt: %d, e-util: %d%%\n",
	cblock.mask_size, cblock.count,
	xpercentInt(cblock.count, cblock.capacity));
    /* check version requirements (both ways) */
    if (cblock.ver.required > CacheDigestVer.current) {
	debug(72, 1) ("%s digest requires version %d; have: %d\n",
	    peer->host, cblock.ver.required, CacheDigestVer.current);
	return 0;
    }
    if (cblock.ver.current < CacheDigestVer.required) {
	debug(72, 1) ("%s digest is version %d; we require: %d\n",
	    peer->host, cblock.ver.current, CacheDigestVer.required);
	return 0;
    }
    /* check consistency */
    if (cblock.ver.required > cblock.ver.current ||
	cblock.mask_size <= 0 || cblock.capacity <= 0 ||
	cblock.bits_per_entry <= 0 || cblock.hash_func_count <= 0) {
	debug(72, 0) ("%s digest cblock is corrupted.\n", peer->host);
	return 0;
    }
    /* check consistency further */
    if (cblock.mask_size != cacheDigestCalcMaskSize(cblock.capacity, cblock.bits_per_entry)) {
	debug(72, 0) ("%s digest cblock is corrupted (mask size mismatch: %d ? %d).\n",
	    peer->host, cblock.mask_size, cacheDigestCalcMaskSize(cblock.capacity, cblock.bits_per_entry));
	return 0;
    }
    /* there are some things we cannot do yet */
    if (cblock.hash_func_count != CacheDigestHashFuncCount) {
	debug(72, 0) ("%s digest: unsupported #hash functions: %d ? %d.\n",
	    peer->host, cblock.hash_func_count, CacheDigestHashFuncCount);
	return 0;
    }
    /*
     * no cblock bugs below this point
     */
    /* check size changes */
    if (peer->digest.cd && cblock.mask_size != peer->digest.cd->mask_size) {
	debug(72, 2) ("%s digest changed size: %d -> %d\n",
	    peer->host, cblock.mask_size, peer->digest.cd->mask_size);
	freed_size = peer->digest.cd->mask_size;
	cacheDigestDestroy(peer->digest.cd);
	peer->digest.cd = NULL;
    }
    if (!peer->digest.cd) {
	debug(72, 2) ("creating %s digest; size: %d (%+d) bytes\n",
	    peer->host, cblock.mask_size, (int) (cblock.mask_size - freed_size));
	peer->digest.cd = cacheDigestCreate(cblock.capacity, cblock.bits_per_entry);
	if (cblock.mask_size >= freed_size)
	    kb_incr(&Counter.cd.memory, cblock.mask_size - freed_size);
    }
    assert(peer->digest.cd);
    /* these assignments leave us in an inconsistent state until we finish reading the digest */
    peer->digest.cd->count = cblock.count;
    peer->digest.cd->del_count = cblock.del_count;
    return 1;
}

static int
peerDigestUseful(const peer * peer)
{
    /* TODO: we should calculate the prob of a false hit instead of bit util */
    const int bit_util = cacheDigestBitUtil(peer->digest.cd);
    if (bit_util > 75) {
	debug(72, 0) ("Warning: %s peer digest has too many bits on (%d%%).\n",
	    peer->host, bit_util);
	return 0;
    }
    return 1;
}

#endif
