/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 72    Peer Digest Routines */

#include "squid.h"
#if USE_CACHE_DIGESTS
#include "CacheDigest.h"
#include "CachePeer.h"
#include "event.h"
#include "FwdState.h"
#include "globals.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "internal.h"
#include "MemObject.h"
#include "mime_header.h"
#include "neighbors.h"
#include "PeerDigest.h"
#include "SquidTime.h"
#include "Store.h"
#include "store_key_md5.h"
#include "StoreClient.h"
#include "tools.h"
#include "util.h"

/* local types */

/* local prototypes */
static time_t peerDigestIncDelay(const PeerDigest * pd);
static time_t peerDigestNewDelay(const StoreEntry * e);
static void peerDigestSetCheck(PeerDigest * pd, time_t delay);
static EVH peerDigestCheck;
static void peerDigestRequest(PeerDigest * pd);
static STCB peerDigestHandleReply;
static int peerDigestFetchReply(void *, char *, ssize_t);
int peerDigestSwapInHeaders(void *, char *, ssize_t);
int peerDigestSwapInCBlock(void *, char *, ssize_t);
int peerDigestSwapInMask(void *, char *, ssize_t);
static int peerDigestFetchedEnough(DigestFetchState * fetch, char *buf, ssize_t size, const char *step_name);
static void peerDigestFetchStop(DigestFetchState * fetch, char *buf, const char *reason);
static void peerDigestFetchAbort(DigestFetchState * fetch, char *buf, const char *reason);
static void peerDigestReqFinish(DigestFetchState * fetch, char *buf, int, int, int, const char *reason, int err);
static void peerDigestPDFinish(DigestFetchState * fetch, int pcb_valid, int err);
static void peerDigestFetchFinish(DigestFetchState * fetch, int err);
static void peerDigestFetchSetStats(DigestFetchState * fetch);
static int peerDigestSetCBlock(PeerDigest * pd, const char *buf);
static int peerDigestUseful(const PeerDigest * pd);

/* local constants */
Version const CacheDigestVer = { 5, 3 };

#define StoreDigestCBlockSize sizeof(StoreDigestCBlock)

/* min interval for requesting digests from a given peer */
static const time_t PeerDigestReqMinGap = 5 * 60;   /* seconds */
/* min interval for requesting digests (cumulative request stream) */
static const time_t GlobDigestReqMinGap = 1 * 60;   /* seconds */

/* local vars */

static time_t pd_last_req_time = 0; /* last call to Check */

PeerDigest::PeerDigest(CachePeer * p)
{
    assert(p);

    /*
     * DPW 2007-04-12
     * Lock on to the peer here.  The corresponding cbdataReferenceDone()
     * is in peerDigestDestroy().
     */
    peer = cbdataReference(p);
    /* if peer disappears, we will know it's name */
    host = p->host;

    times.initialized = squid_curtime;
}

CBDATA_CLASS_INIT(PeerDigest);

CBDATA_CLASS_INIT(DigestFetchState);

DigestFetchState::DigestFetchState(PeerDigest *aPd, HttpRequest *req) :
    pd(cbdataReference(aPd)),
    entry(NULL),
    old_entry(NULL),
    sc(NULL),
    old_sc(NULL),
    request(req),
    offset(0),
    mask_offset(0),
    start_time(squid_curtime),
    resp_time(0),
    expires(0),
    bufofs(0),
    state(DIGEST_READ_REPLY)
{
    HTTPMSGLOCK(request);

    sent.msg = 0;
    sent.bytes = 0;

    recv.msg = 0;
    recv.bytes = 0;

    *buf = 0;
}

DigestFetchState::~DigestFetchState()
{
    /* unlock everything */
    storeUnregister(sc, entry, this);

    entry->unlock("DigestFetchState destructed");
    entry = NULL;

    HTTPMSGUNLOCK(request);

    assert(pd == NULL);
}

/* allocate new peer digest, call Init, and lock everything */
void
peerDigestCreate(CachePeer * p)
{
    assert(p);

    PeerDigest *pd = new PeerDigest(p);

    // TODO: make CachePeer member a CbcPointer
    p->digest = cbdataReference(pd);

    // lock a reference to pd again to prevent the PeerDigest
    // disappearing during peerDigestDestroy() when
    // cbdataReferenceValidDone is called.
    // TODO test if it can be moved into peerDigestDestroy() or
    //      if things can break earlier (eg CachePeer death).
    (void)cbdataReference(pd);
}

/* call Clean and free/unlock everything */
static void
peerDigestDestroy(PeerDigest * pd)
{
    void *p;
    assert(pd);
    void * peerTmp = pd->peer;

    /*
     * DPW 2007-04-12
     * We locked the peer in PeerDigest constructor, this is
     * where we unlock it.
     */
    if (cbdataReferenceValidDone(peerTmp, &p)) {
        // we locked the p->digest in peerDigestCreate()
        // this is where we unlock that
        cbdataReferenceDone(static_cast<CachePeer *>(p)->digest);
    }

    delete pd;
}

PeerDigest::~PeerDigest()
{
    delete cd;
    // req_result pointer is not owned by us
}

/* called by peer to indicate that somebody actually needs this digest */
void
peerDigestNeeded(PeerDigest * pd)
{
    assert(pd);
    assert(!pd->flags.needed);
    assert(!pd->cd);

    pd->flags.needed = true;
    pd->times.needed = squid_curtime;
    peerDigestSetCheck(pd, 0);  /* check asap */
}

/* currently we do not have a reason to disable without destroying */
#if FUTURE_CODE
/* disables peer for good */
static void
peerDigestDisable(PeerDigest * pd)
{
    debugs(72, 2, "peerDigestDisable: peer " << pd->host.buf() << " disabled for good");
    pd->times.disabled = squid_curtime;
    pd->times.next_check = -1;  /* never */
    pd->flags.usable = 0;

    delete pd->cd
    pd->cd = nullptr;

    /* we do not destroy the pd itself to preserve its "history" and stats */
}

#endif

/* increment retry delay [after an unsuccessful attempt] */
static time_t
peerDigestIncDelay(const PeerDigest * pd)
{
    assert(pd);
    return pd->times.retry_delay > 0 ?
           2 * pd->times.retry_delay :  /* exponential backoff */
           PeerDigestReqMinGap; /* minimal delay */
}

/* artificially increases Expires: setting to avoid race conditions
 * returns the delay till that [increased] expiration time */
static time_t
peerDigestNewDelay(const StoreEntry * e)
{
    assert(e);

    if (e->expires > 0)
        return e->expires + PeerDigestReqMinGap - squid_curtime;

    return PeerDigestReqMinGap;
}

/* registers next digest verification */
static void
peerDigestSetCheck(PeerDigest * pd, time_t delay)
{
    eventAdd("peerDigestCheck", peerDigestCheck, pd, (double) delay, 1);
    pd->times.next_check = squid_curtime + delay;
    debugs(72, 3, "peerDigestSetCheck: will check peer " << pd->host << " in " << delay << " secs");
}

/*
 * called when peer is about to disappear or have already disappeared
 */
void
peerDigestNotePeerGone(PeerDigest * pd)
{
    if (pd->flags.requested) {
        debugs(72, 2, "peerDigest: peer " << pd->host << " gone, will destroy after fetch.");
        /* do nothing now, the fetching chain will notice and take action */
    } else {
        debugs(72, 2, "peerDigest: peer " << pd->host << " is gone, destroying now.");
        peerDigestDestroy(pd);
    }
}

/* callback for eventAdd() (with peer digest locked)
 * request new digest if our copy is too old or if we lack one;
 * schedule next check otherwise */
static void
peerDigestCheck(void *data)
{
    PeerDigest *pd = (PeerDigest *)data;
    time_t req_time;

    assert(!pd->flags.requested);

    pd->times.next_check = 0;   /* unknown */

    if (!cbdataReferenceValid(pd->peer)) {
        peerDigestNotePeerGone(pd);
        return;
    }

    debugs(72, 3, "peerDigestCheck: peer " <<  pd->peer->host << ":" << pd->peer->http_port);
    debugs(72, 3, "peerDigestCheck: time: " << squid_curtime <<
           ", last received: " << (long int) pd->times.received << "  (" <<
           std::showpos << (int) (squid_curtime - pd->times.received) << ")");

    /* decide when we should send the request:
     * request now unless too close to other requests */
    req_time = squid_curtime;

    /* per-peer limit */

    if (req_time - pd->times.received < PeerDigestReqMinGap) {
        debugs(72, 2, "peerDigestCheck: " << pd->host <<
               ", avoiding close peer requests (" <<
               (int) (req_time - pd->times.received) << " < " <<
               (int) PeerDigestReqMinGap << " secs).");

        req_time = pd->times.received + PeerDigestReqMinGap;
    }

    /* global limit */
    if (req_time - pd_last_req_time < GlobDigestReqMinGap) {
        debugs(72, 2, "peerDigestCheck: " << pd->host <<
               ", avoiding close requests (" <<
               (int) (req_time - pd_last_req_time) << " < " <<
               (int) GlobDigestReqMinGap << " secs).");

        req_time = pd_last_req_time + GlobDigestReqMinGap;
    }

    if (req_time <= squid_curtime)
        peerDigestRequest(pd);  /* will set pd->flags.requested */
    else
        peerDigestSetCheck(pd, req_time - squid_curtime);
}

/* ask store for a digest */
static void
peerDigestRequest(PeerDigest * pd)
{
    CachePeer *p = pd->peer;
    StoreEntry *e, *old_e;
    char *url = NULL;
    HttpRequest *req;
    StoreIOBuffer tempBuffer;

    pd->req_result = NULL;
    pd->flags.requested = true;

    /* compute future request components */

    if (p->digest_url)
        url = xstrdup(p->digest_url);
    else
        url = xstrdup(internalRemoteUri(p->secure.encryptTransport, p->host, p->http_port, "/squid-internal-periodic/", SBuf(StoreDigestFileName)));
    debugs(72, 2, url);

    const MasterXaction::Pointer mx = new MasterXaction(XactionInitiator::initCacheDigest);
    req = HttpRequest::FromUrl(url, mx);

    assert(req);

    /* add custom headers */
    assert(!req->header.len);

    req->header.putStr(Http::HdrType::ACCEPT, StoreDigestMimeStr);

    req->header.putStr(Http::HdrType::ACCEPT, "text/html");

    if (p->login &&
            p->login[0] != '*' &&
            strcmp(p->login, "PASS") != 0 &&
            strcmp(p->login, "PASSTHRU") != 0 &&
            strncmp(p->login, "NEGOTIATE",9) != 0 &&
            strcmp(p->login, "PROXYPASS") != 0) {
        req->url.userInfo(SBuf(p->login)); // XXX: performance regression make peer login SBuf as well.
    }
    /* create fetch state structure */
    DigestFetchState *fetch = new DigestFetchState(pd, req);

    /* update timestamps */
    pd->times.requested = squid_curtime;
    pd_last_req_time = squid_curtime;
    req->flags.cachable = true;

    /* the rest is based on clientReplyContext::processExpired() */
    req->flags.refresh = true;

    old_e = fetch->old_entry = storeGetPublicByRequest(req);

    if (old_e) {
        debugs(72, 5, "found old " << *old_e);

        old_e->lock("peerDigestRequest");
        old_e->ensureMemObject(url, url, req->method);

        fetch->old_sc = storeClientListAdd(old_e, fetch);
    }

    e = fetch->entry = storeCreateEntry(url, url, req->flags, req->method);
    debugs(72, 5, "created " << *e);
    assert(EBIT_TEST(e->flags, KEY_PRIVATE));
    fetch->sc = storeClientListAdd(e, fetch);
    /* set lastmod to trigger IMS request if possible */

    if (old_e)
        e->lastModified(old_e->lastModified());

    /* push towards peer cache */
    FwdState::fwdStart(Comm::ConnectionPointer(), e, req);

    tempBuffer.offset = 0;

    tempBuffer.length = SM_PAGE_SIZE;

    tempBuffer.data = fetch->buf;

    storeClientCopy(fetch->sc, e, tempBuffer,
                    peerDigestHandleReply, fetch);

    safe_free(url);
}

/* Handle the data copying .. */

/*
 * This routine handles the copy data and then redirects the
 * copy to a bunch of subfunctions depending upon the copy state.
 * It also tracks the buffer offset and "seen", since I'm actually
 * not interested in rewriting everything to suit my little idea.
 */
static void
peerDigestHandleReply(void *data, StoreIOBuffer receivedData)
{
    DigestFetchState *fetch = (DigestFetchState *)data;
    int retsize = -1;
    digest_read_state_t prevstate;
    int newsize;

    assert(fetch->pd && receivedData.data);
    /* The existing code assumes that the received pointer is
     * where we asked the data to be put
     */
    assert(fetch->buf + fetch->bufofs == receivedData.data);

    /* Update the buffer size */
    fetch->bufofs += receivedData.length;

    assert(fetch->bufofs <= SM_PAGE_SIZE);

    /* If we've fetched enough, return */

    if (peerDigestFetchedEnough(fetch, fetch->buf, fetch->bufofs, "peerDigestHandleReply"))
        return;

    /* Call the right function based on the state */
    /* (Those functions will update the state if needed) */

    /* Give us a temporary reference. Some of the calls we make may
     * try to destroy the fetch structure, and we like to know if they
     * do
     */
    CbcPointer<DigestFetchState> tmpLock = fetch;

    /* Repeat this loop until we're out of data OR the state changes */
    /* (So keep going if the state has changed and we still have data */
    do {
        prevstate = fetch->state;

        switch (fetch->state) {

        case DIGEST_READ_REPLY:
            retsize = peerDigestFetchReply(fetch, fetch->buf, fetch->bufofs);
            break;

        case DIGEST_READ_HEADERS:
            retsize = peerDigestSwapInHeaders(fetch, fetch->buf, fetch->bufofs);
            break;

        case DIGEST_READ_CBLOCK:
            retsize = peerDigestSwapInCBlock(fetch, fetch->buf, fetch->bufofs);
            break;

        case DIGEST_READ_MASK:
            retsize = peerDigestSwapInMask(fetch, fetch->buf, fetch->bufofs);
            break;

        case DIGEST_READ_NONE:
            break;

        case DIGEST_READ_DONE:
            return;
            break;

        default:
            fatal("Bad digest transfer mode!\n");
        }

        if (retsize < 0)
            return;

        /*
         * The returned size indicates how much of the buffer was read -
         * so move the remainder of the buffer to the beginning
         * and update the bufofs / bufsize
         */
        newsize = fetch->bufofs - retsize;

        memmove(fetch->buf, fetch->buf + retsize, fetch->bufofs - newsize);

        fetch->bufofs = newsize;

    } while (cbdataReferenceValid(fetch) && prevstate != fetch->state && fetch->bufofs > 0);

    /* Update the copy offset */
    fetch->offset += receivedData.length;

    /* Schedule another copy */
    if (cbdataReferenceValid(fetch)) {
        StoreIOBuffer tempBuffer;
        tempBuffer.offset = fetch->offset;
        tempBuffer.length = SM_PAGE_SIZE - fetch->bufofs;
        tempBuffer.data = fetch->buf + fetch->bufofs;
        storeClientCopy(fetch->sc, fetch->entry, tempBuffer,
                        peerDigestHandleReply, fetch);
    }
}

/* wait for full http headers to be received then parse them */
/*
 * This routine handles parsing the reply line.
 * If the reply line indicates an OK, the same data is thrown
 * to SwapInHeaders(). If the reply line is a NOT_MODIFIED,
 * we simply stop parsing.
 */
static int
peerDigestFetchReply(void *data, char *buf, ssize_t size)
{
    DigestFetchState *fetch = (DigestFetchState *)data;
    PeerDigest *pd = fetch->pd;
    size_t hdr_size;
    assert(pd && buf);
    assert(!fetch->offset);

    assert(fetch->state == DIGEST_READ_REPLY);

    if (peerDigestFetchedEnough(fetch, buf, size, "peerDigestFetchReply"))
        return -1;

    if ((hdr_size = headersEnd(buf, size))) {
        HttpReply const *reply = fetch->entry->getReply();
        assert(reply);
        assert(reply->sline.status() != Http::scNone);
        const Http::StatusCode status = reply->sline.status();
        debugs(72, 3, "peerDigestFetchReply: " << pd->host << " status: " << status <<
               ", expires: " << (long int) reply->expires << " (" << std::showpos <<
               (int) (reply->expires - squid_curtime) << ")");

        /* this "if" is based on clientHandleIMSReply() */

        if (status == Http::scNotModified) {
            /* our old entry is fine */
            assert(fetch->old_entry);

            if (!fetch->old_entry->mem_obj->request) {
                fetch->old_entry->mem_obj->request = fetch->entry->mem_obj->request;
                HTTPMSGLOCK(fetch->old_entry->mem_obj->request);
            }

            assert(fetch->old_entry->mem_obj->request);

            Store::Root().updateOnNotModified(fetch->old_entry, *fetch->entry);

            /* get rid of 304 reply */
            storeUnregister(fetch->sc, fetch->entry, fetch);

            fetch->entry->unlock("peerDigestFetchReply 304");

            fetch->entry = fetch->old_entry;

            fetch->old_entry = NULL;

            /* preserve request -- we need its size to update counters */
            /* requestUnlink(r); */
            /* fetch->entry->mem_obj->request = NULL; */
        } else if (status == Http::scOkay) {
            /* get rid of old entry if any */

            if (fetch->old_entry) {
                debugs(72, 3, "peerDigestFetchReply: got new digest, releasing old one");
                storeUnregister(fetch->old_sc, fetch->old_entry, fetch);
                fetch->old_entry->releaseRequest();
                fetch->old_entry->unlock("peerDigestFetchReply 200");
                fetch->old_entry = NULL;
            }
        } else {
            /* some kind of a bug */
            peerDigestFetchAbort(fetch, buf, reply->sline.reason());
            return -1;      /* XXX -1 will abort stuff in ReadReply! */
        }

        /* must have a ready-to-use store entry if we got here */
        /* can we stay with the old in-memory digest? */
        if (status == Http::scNotModified && fetch->pd->cd) {
            peerDigestFetchStop(fetch, buf, "Not modified");
            fetch->state = DIGEST_READ_DONE;
        } else {
            fetch->state = DIGEST_READ_HEADERS;
        }
    } else {
        /* need more data, do we have space? */

        if (size >= SM_PAGE_SIZE)
            peerDigestFetchAbort(fetch, buf, "reply header too big");
    }

    /* We don't want to actually ack that we've handled anything,
     * otherwise SwapInHeaders() won't get the reply line .. */
    return 0;
}

/* fetch headers from disk, pass on to SwapInCBlock */
int
peerDigestSwapInHeaders(void *data, char *buf, ssize_t size)
{
    DigestFetchState *fetch = (DigestFetchState *)data;
    size_t hdr_size;

    assert(fetch->state == DIGEST_READ_HEADERS);

    if (peerDigestFetchedEnough(fetch, buf, size, "peerDigestSwapInHeaders"))
        return -1;

    assert(!fetch->offset);

    if ((hdr_size = headersEnd(buf, size))) {
        assert(fetch->entry->getReply());
        assert(fetch->entry->getReply()->sline.status() != Http::scNone);

        if (fetch->entry->getReply()->sline.status() != Http::scOkay) {
            debugs(72, DBG_IMPORTANT, "peerDigestSwapInHeaders: " << fetch->pd->host <<
                   " status " << fetch->entry->getReply()->sline.status() <<
                   " got cached!");

            peerDigestFetchAbort(fetch, buf, "internal status error");
            return -1;
        }

        fetch->state = DIGEST_READ_CBLOCK;
        return hdr_size;    /* Say how much data we read */
    }

    /* need more data, do we have space? */
    if (size >= SM_PAGE_SIZE) {
        peerDigestFetchAbort(fetch, buf, "stored header too big");
        return -1;
    }

    return 0;       /* We need to read more to parse .. */
}

int
peerDigestSwapInCBlock(void *data, char *buf, ssize_t size)
{
    DigestFetchState *fetch = (DigestFetchState *)data;

    assert(fetch->state == DIGEST_READ_CBLOCK);

    if (peerDigestFetchedEnough(fetch, buf, size, "peerDigestSwapInCBlock"))
        return -1;

    if (size >= (ssize_t)StoreDigestCBlockSize) {
        PeerDigest *pd = fetch->pd;

        assert(pd && fetch->entry->getReply());

        if (peerDigestSetCBlock(pd, buf)) {
            /* XXX: soon we will have variable header size */
            /* switch to CD buffer and fetch digest guts */
            buf = NULL;
            assert(pd->cd->mask);
            fetch->state = DIGEST_READ_MASK;
            return StoreDigestCBlockSize;
        } else {
            peerDigestFetchAbort(fetch, buf, "invalid digest cblock");
            return -1;
        }
    }

    /* need more data, do we have space? */
    if (size >= SM_PAGE_SIZE) {
        peerDigestFetchAbort(fetch, buf, "digest cblock too big");
        return -1;
    }

    return 0;       /* We need more data */
}

int
peerDigestSwapInMask(void *data, char *buf, ssize_t size)
{
    DigestFetchState *fetch = (DigestFetchState *)data;
    PeerDigest *pd;

    pd = fetch->pd;
    assert(pd->cd && pd->cd->mask);

    /*
     * NOTENOTENOTENOTENOTE: buf doesn't point to pd->cd->mask anymore!
     * we need to do the copy ourselves!
     */
    memcpy(pd->cd->mask + fetch->mask_offset, buf, size);

    /* NOTE! buf points to the middle of pd->cd->mask! */

    if (peerDigestFetchedEnough(fetch, NULL, size, "peerDigestSwapInMask"))
        return -1;

    fetch->mask_offset += size;

    if (fetch->mask_offset >= pd->cd->mask_size) {
        debugs(72, 2, "peerDigestSwapInMask: Done! Got " <<
               fetch->mask_offset << ", expected " << pd->cd->mask_size);
        assert(fetch->mask_offset == pd->cd->mask_size);
        assert(peerDigestFetchedEnough(fetch, NULL, 0, "peerDigestSwapInMask"));
        return -1;      /* XXX! */
    }

    /* We always read everything, so return size */
    return size;
}

static int
peerDigestFetchedEnough(DigestFetchState * fetch, char *buf, ssize_t size, const char *step_name)
{
    PeerDigest *pd = NULL;
    const char *host = "<unknown>"; /* peer host */
    const char *reason = NULL;  /* reason for completion */
    const char *no_bug = NULL;  /* successful completion if set */
    const int pdcb_valid = cbdataReferenceValid(fetch->pd);
    const int pcb_valid = cbdataReferenceValid(fetch->pd->peer);

    /* test possible exiting conditions (the same for most steps!)
     * cases marked with '?!' should not happen */

    if (!reason) {
        if (!(pd = fetch->pd))
            reason = "peer digest disappeared?!";

#if DONT            /* WHY NOT? /HNO */

        else if (!cbdataReferenceValid(pd))
            reason = "invalidated peer digest?!";

#endif

        else
            host = pd->host.termedBuf();
    }

    debugs(72, 6, step_name << ": peer " << host << ", offset: " <<
           fetch->offset << " size: " << size << ".");

    /* continue checking (with pd and host known and valid) */

    if (!reason) {
        if (!cbdataReferenceValid(pd->peer))
            reason = "peer disappeared";
        else if (size < 0)
            reason = "swap failure";
        else if (!fetch->entry)
            reason = "swap aborted?!";
        else if (EBIT_TEST(fetch->entry->flags, ENTRY_ABORTED))
            reason = "swap aborted";
    }

    /* continue checking (maybe-successful eof case) */
    if (!reason && !size) {
        if (!pd->cd)
            reason = "null digest?!";
        else if (fetch->mask_offset != pd->cd->mask_size)
            reason = "premature end of digest?!";
        else if (!peerDigestUseful(pd))
            reason = "useless digest";
        else
            reason = no_bug = "success";
    }

    /* finish if we have a reason */
    if (reason) {
        const int level = strstr(reason, "?!") ? 1 : 3;
        debugs(72, level, "" << step_name << ": peer " << host << ", exiting after '" << reason << "'");
        peerDigestReqFinish(fetch, buf,
                            1, pdcb_valid, pcb_valid, reason, !no_bug);
    } else {
        /* paranoid check */
        assert(pdcb_valid && pcb_valid);
    }

    return reason != NULL;
}

/* call this when all callback data is valid and fetch must be stopped but
 * no error has occurred (e.g. we received 304 reply and reuse old digest) */
static void
peerDigestFetchStop(DigestFetchState * fetch, char *buf, const char *reason)
{
    assert(reason);
    debugs(72, 2, "peerDigestFetchStop: peer " << fetch->pd->host << ", reason: " << reason);
    peerDigestReqFinish(fetch, buf, 1, 1, 1, reason, 0);
}

/* call this when all callback data is valid but something bad happened */
static void
peerDigestFetchAbort(DigestFetchState * fetch, char *buf, const char *reason)
{
    assert(reason);
    debugs(72, 2, "peerDigestFetchAbort: peer " << fetch->pd->host << ", reason: " << reason);
    peerDigestReqFinish(fetch, buf, 1, 1, 1, reason, 1);
}

/* complete the digest transfer, update stats, unlock/release everything */
static void
peerDigestReqFinish(DigestFetchState * fetch, char *buf,
                    int fcb_valid, int pdcb_valid, int pcb_valid,
                    const char *reason, int err)
{
    assert(reason);

    /* must go before peerDigestPDFinish */

    if (pdcb_valid) {
        fetch->pd->flags.requested = false;
        fetch->pd->req_result = reason;
    }

    /* schedule next check if peer is still out there */
    if (pcb_valid) {
        PeerDigest *pd = fetch->pd;

        if (err) {
            pd->times.retry_delay = peerDigestIncDelay(pd);
            peerDigestSetCheck(pd, pd->times.retry_delay);
        } else {
            pd->times.retry_delay = 0;
            peerDigestSetCheck(pd, peerDigestNewDelay(fetch->entry));
        }
    }

    /* note: order is significant */
    if (fcb_valid)
        peerDigestFetchSetStats(fetch);

    if (pdcb_valid)
        peerDigestPDFinish(fetch, pcb_valid, err);

    if (fcb_valid)
        peerDigestFetchFinish(fetch, err);
}

/* destroys digest if peer disappeared
 * must be called only when fetch and pd cbdata are valid */
static void
peerDigestPDFinish(DigestFetchState * fetch, int pcb_valid, int err)
{
    PeerDigest *pd = fetch->pd;
    const char *host = pd->host.termedBuf();

    pd->times.received = squid_curtime;
    pd->times.req_delay = fetch->resp_time;
    pd->stats.sent.kbytes += fetch->sent.bytes;
    pd->stats.recv.kbytes += fetch->recv.bytes;
    pd->stats.sent.msgs += fetch->sent.msg;
    pd->stats.recv.msgs += fetch->recv.msg;

    if (err) {
        debugs(72, DBG_IMPORTANT, "" << (pcb_valid ? "temporary " : "" ) << "disabling (" << pd->req_result << ") digest from " << host);

        delete pd->cd;
        pd->cd = nullptr;

        pd->flags.usable = false;

        if (!pcb_valid)
            peerDigestNotePeerGone(pd);
    } else {
        assert(pcb_valid);

        pd->flags.usable = true;

        /* XXX: ugly condition, but how? */

        if (fetch->entry->store_status == STORE_OK)
            debugs(72, 2, "re-used old digest from " << host);
        else
            debugs(72, 2, "received valid digest from " << host);
    }

    cbdataReferenceDone(fetch->pd);
}

/* free fetch state structures
 * must be called only when fetch cbdata is valid */
static void
peerDigestFetchFinish(DigestFetchState * fetch, int err)
{
    assert(fetch->entry && fetch->request);

    if (fetch->old_entry) {
        debugs(72, 3, "peerDigestFetchFinish: deleting old entry");
        storeUnregister(fetch->old_sc, fetch->old_entry, fetch);
        fetch->old_entry->releaseRequest();
        fetch->old_entry->unlock("peerDigestFetchFinish old");
        fetch->old_entry = NULL;
    }

    /* update global stats */
    statCounter.cd.kbytes_sent += fetch->sent.bytes;
    statCounter.cd.kbytes_recv += fetch->recv.bytes;
    statCounter.cd.msgs_sent += fetch->sent.msg;
    statCounter.cd.msgs_recv += fetch->recv.msg;

    delete fetch;
}

/* calculate fetch stats after completion */
static void
peerDigestFetchSetStats(DigestFetchState * fetch)
{
    MemObject *mem;
    assert(fetch->entry && fetch->request);

    mem = fetch->entry->mem_obj;
    assert(mem);

    /* XXX: outgoing numbers are not precise */
    /* XXX: we must distinguish between 304 hits and misses here */
    fetch->sent.bytes = fetch->request->prefixLen();
    /* XXX: this is slightly wrong: we don't KNOW that the entire memobject
     * was fetched. We only know how big it is
     */
    fetch->recv.bytes = mem->size();
    fetch->sent.msg = fetch->recv.msg = 1;
    fetch->expires = fetch->entry->expires;
    fetch->resp_time = squid_curtime - fetch->start_time;

    debugs(72, 3, "peerDigestFetchFinish: recv " << fetch->recv.bytes <<
           " bytes in " << (int) fetch->resp_time << " secs");

    debugs(72, 3, "peerDigestFetchFinish: expires: " <<
           (long int) fetch->expires << " (" << std::showpos <<
           (int) (fetch->expires - squid_curtime) << "), lmt: " <<
           std::noshowpos << (long int) fetch->entry->lastModified() << " (" <<
           std::showpos << (int) (fetch->entry->lastModified() - squid_curtime) <<
           ")");

}

static int
peerDigestSetCBlock(PeerDigest * pd, const char *buf)
{
    StoreDigestCBlock cblock;
    int freed_size = 0;
    const char *host = pd->host.termedBuf();

    memcpy(&cblock, buf, sizeof(cblock));
    /* network -> host conversions */
    cblock.ver.current = ntohs(cblock.ver.current);
    cblock.ver.required = ntohs(cblock.ver.required);
    cblock.capacity = ntohl(cblock.capacity);
    cblock.count = ntohl(cblock.count);
    cblock.del_count = ntohl(cblock.del_count);
    cblock.mask_size = ntohl(cblock.mask_size);
    debugs(72, 2, "got digest cblock from " << host << "; ver: " <<
           (int) cblock.ver.current << " (req: " << (int) cblock.ver.required <<
           ")");

    debugs(72, 2, "\t size: " <<
           cblock.mask_size << " bytes, e-cnt: " <<
           cblock.count << ", e-util: " <<
           xpercentInt(cblock.count, cblock.capacity) << "%" );
    /* check version requirements (both ways) */

    if (cblock.ver.required > CacheDigestVer.current) {
        debugs(72, DBG_IMPORTANT, "" << host << " digest requires version " <<
               cblock.ver.required << "; have: " << CacheDigestVer.current);

        return 0;
    }

    if (cblock.ver.current < CacheDigestVer.required) {
        debugs(72, DBG_IMPORTANT, "" << host << " digest is version " <<
               cblock.ver.current << "; we require: " <<
               CacheDigestVer.required);

        return 0;
    }

    /* check consistency */
    if (cblock.ver.required > cblock.ver.current ||
            cblock.mask_size <= 0 || cblock.capacity <= 0 ||
            cblock.bits_per_entry <= 0 || cblock.hash_func_count <= 0) {
        debugs(72, DBG_CRITICAL, "" << host << " digest cblock is corrupted.");
        return 0;
    }

    /* check consistency further */
    if ((size_t)cblock.mask_size != CacheDigest::CalcMaskSize(cblock.capacity, cblock.bits_per_entry)) {
        debugs(72, DBG_CRITICAL, host << " digest cblock is corrupted " <<
               "(mask size mismatch: " << cblock.mask_size << " ? " <<
               CacheDigest::CalcMaskSize(cblock.capacity, cblock.bits_per_entry)
               << ").");
        return 0;
    }

    /* there are some things we cannot do yet */
    if (cblock.hash_func_count != CacheDigestHashFuncCount) {
        debugs(72, DBG_CRITICAL, "" << host << " digest: unsupported #hash functions: " <<
               cblock.hash_func_count << " ? " << CacheDigestHashFuncCount << ".");
        return 0;
    }

    /*
     * no cblock bugs below this point
     */
    /* check size changes */
    if (pd->cd && cblock.mask_size != (ssize_t)pd->cd->mask_size) {
        debugs(72, 2, host << " digest changed size: " << cblock.mask_size <<
               " -> " << pd->cd->mask_size);
        freed_size = pd->cd->mask_size;
        delete pd->cd;
        pd->cd = nullptr;
    }

    if (!pd->cd) {
        debugs(72, 2, "creating " << host << " digest; size: " << cblock.mask_size << " (" <<
               std::showpos <<  (int) (cblock.mask_size - freed_size) << ") bytes");
        pd->cd = new CacheDigest(cblock.capacity, cblock.bits_per_entry);

        if (cblock.mask_size >= freed_size)
            statCounter.cd.memory += (cblock.mask_size - freed_size);
    }

    assert(pd->cd);
    /* these assignments leave us in an inconsistent state until we finish reading the digest */
    pd->cd->count = cblock.count;
    pd->cd->del_count = cblock.del_count;
    return 1;
}

static int
peerDigestUseful(const PeerDigest * pd)
{
    /* TODO: we should calculate the prob of a false hit instead of bit util */
    const auto bit_util = pd->cd->usedMaskPercent();

    if (bit_util > 65.0) {
        debugs(72, DBG_CRITICAL, "Warning: " << pd->host <<
               " peer digest has too many bits on (" << bit_util << "%).");
        return 0;
    }

    return 1;
}

static int
saneDiff(time_t diff)
{
    return abs((int) diff) > squid_curtime / 2 ? 0 : diff;
}

void
peerDigestStatsReport(const PeerDigest * pd, StoreEntry * e)
{
#define f2s(flag) (pd->flags.flag ? "yes" : "no")
#define appendTime(tm) storeAppendPrintf(e, "%s\t %10ld\t %+d\t %+d\n", \
    ""#tm, (long int)pd->times.tm, \
    saneDiff(pd->times.tm - squid_curtime), \
    saneDiff(pd->times.tm - pd->times.initialized))

    assert(pd);

    const char *host = pd->host.termedBuf();
    storeAppendPrintf(e, "\npeer digest from %s\n", host);

    cacheDigestGuessStatsReport(&pd->stats.guess, e, host);

    storeAppendPrintf(e, "\nevent\t timestamp\t secs from now\t secs from init\n");
    appendTime(initialized);
    appendTime(needed);
    appendTime(requested);
    appendTime(received);
    appendTime(next_check);

    storeAppendPrintf(e, "peer digest state:\n");
    storeAppendPrintf(e, "\tneeded: %3s, usable: %3s, requested: %3s\n",
                      f2s(needed), f2s(usable), f2s(requested));
    storeAppendPrintf(e, "\n\tlast retry delay: %d secs\n",
                      (int) pd->times.retry_delay);
    storeAppendPrintf(e, "\tlast request response time: %d secs\n",
                      (int) pd->times.req_delay);
    storeAppendPrintf(e, "\tlast request result: %s\n",
                      pd->req_result ? pd->req_result : "(none)");

    storeAppendPrintf(e, "\npeer digest traffic:\n");
    storeAppendPrintf(e, "\trequests sent: %d, volume: %d KB\n",
                      pd->stats.sent.msgs, (int) pd->stats.sent.kbytes.kb);
    storeAppendPrintf(e, "\treplies recv:  %d, volume: %d KB\n",
                      pd->stats.recv.msgs, (int) pd->stats.recv.kbytes.kb);

    storeAppendPrintf(e, "\npeer digest structure:\n");

    if (pd->cd)
        cacheDigestReport(pd->cd, host, e);
    else
        storeAppendPrintf(e, "\tno in-memory copy\n");
}

#endif

