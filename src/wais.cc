
/*
 * $Id: wais.cc,v 1.140 2002/10/13 20:35:06 robertc Exp $
 *
 * DEBUG: section 24    WAIS Relay
 * AUTHOR: Harvest Derived
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
#include "Store.h"

typedef struct {
    int fd;
    StoreEntry *entry;
    method_t method;
    const HttpHeader *request_hdr;
    char url[MAX_URL];
    request_t *request;
    FwdState *fwd;
} WaisStateData;

static PF waisStateFree;
static PF waisTimeout;
static PF waisReadReply;
static CWCB waisSendComplete;
static PF waisSendRequest;

static void
waisStateFree(int fdnotused, void *data)
{
    WaisStateData *waisState = (WaisStateData *)data;
    if (waisState == NULL)
	return;
    storeUnlockObject(waisState->entry);
    requestUnlink(waisState->request);
    cbdataFree(waisState);
}

/* This will be called when socket lifetime is expired. */
static void
waisTimeout(int fd, void *data)
{
    WaisStateData *waisState = (WaisStateData *)data;
    StoreEntry *entry = waisState->entry;
    debug(24, 4) ("waisTimeout: FD %d: '%s'\n", fd, storeUrl(entry));
    if (entry->store_status == STORE_PENDING) {
	if (entry->mem_obj->inmem_hi == 0) {
	    fwdFail(waisState->fwd,
		errorCon(ERR_READ_TIMEOUT, HTTP_GATEWAY_TIMEOUT));
	}
    }
    comm_close(fd);
}

/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
static void
waisReadReply(int fd, void *data)
{
    WaisStateData *waisState = (WaisStateData *)data;
    LOCAL_ARRAY(char, buf, 4096);
    StoreEntry *entry = waisState->entry;
    int len;
    int clen;
    int bin;
    size_t read_sz;
#if DELAY_POOLS
    delay_id delay_id = delayMostBytesAllowed(entry->mem_obj);
#endif
    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	comm_close(fd);
	return;
    }
    errno = 0;
    read_sz = 4096;
#if DELAY_POOLS
    read_sz = delayBytesWanted(delay_id, 1, read_sz);
#endif
    statCounter.syscalls.sock.reads++;
    len = FD_READ_METHOD(fd, buf, read_sz);
    if (len > 0) {
	fd_bytes(fd, len, FD_READ);
#if DELAY_POOLS
	delayBytesIn(delay_id, len);
#endif
	kb_incr(&statCounter.server.all.kbytes_in, len);
	kb_incr(&statCounter.server.other.kbytes_in, len);
    }
    debug(24, 5) ("waisReadReply: FD %d read len:%d\n", fd, len);
    if (len > 0) {
	commSetTimeout(fd, Config.Timeout.read, NULL, NULL);
	IOStats.Wais.reads++;
	for (clen = len - 1, bin = 0; clen; bin++)
	    clen >>= 1;
	IOStats.Wais.read_hist[bin]++;
    }
    if (len < 0) {
	debug(50, 1) ("waisReadReply: FD %d: read failure: %s.\n",
	    fd, xstrerror());
	if (ignoreErrno(errno)) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    commSetSelect(fd, COMM_SELECT_READ,
		waisReadReply, waisState, 0);
	} else {
	    ErrorState *err;
	    EBIT_CLR(entry->flags, ENTRY_CACHABLE);
	    storeReleaseRequest(entry);
	    err = errorCon(ERR_READ_ERROR, HTTP_INTERNAL_SERVER_ERROR);
	    err->xerrno = errno;
	    err->request = requestLink(waisState->request);
	    errorAppendEntry(entry, err);
	    comm_close(fd);
	}
    } else if (len == 0 && entry->mem_obj->inmem_hi == 0) {
	ErrorState *err;
	err = errorCon(ERR_ZERO_SIZE_OBJECT, HTTP_SERVICE_UNAVAILABLE);
	err->xerrno = errno;
	err->request = requestLink(waisState->request);
	errorAppendEntry(entry, err);
	comm_close(fd);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	entry->expires = squid_curtime;
	fwdComplete(waisState->fwd);
	comm_close(fd);
    } else {
	storeAppend(entry, buf, len);
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    waisReadReply,
	    waisState, 0);
    }
}

/* This will be called when request write is complete. Schedule read of
 * reply. */
static void
waisSendComplete(int fd, char *bufnotused, size_t size, comm_err_t errflag, void *data)
{
    WaisStateData *waisState = (WaisStateData *)data;
    StoreEntry *entry = waisState->entry;
    debug(24, 5) ("waisSendComplete: FD %d size: %d errflag: %d\n",
	fd, (int) size, errflag);
    if (size > 0) {
	fd_bytes(fd, size, FD_WRITE);
	kb_incr(&statCounter.server.all.kbytes_out, size);
	kb_incr(&statCounter.server.other.kbytes_out, size);
    }
    if (errflag == COMM_ERR_CLOSING)
	return;
    if (errflag) {
	ErrorState *err;
	err = errorCon(ERR_WRITE_ERROR, HTTP_SERVICE_UNAVAILABLE);
	err->xerrno = errno;
	err->request = requestLink(waisState->request);
	errorAppendEntry(entry, err);
	comm_close(fd);
    } else {
	/* Schedule read reply. */
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    waisReadReply,
	    waisState, 0);
	commSetDefer(fd, fwdCheckDeferRead, entry);
    }
}

/* This will be called when connect completes. Write request. */
static void
waisSendRequest(int fd, void *data)
{
    WaisStateData *waisState = (WaisStateData *)data;
    MemBuf mb;
    const char *Method = RequestMethodStr[waisState->method];
    debug(24, 5) ("waisSendRequest: FD %d\n", fd);
    memBufDefInit(&mb);
    memBufPrintf(&mb, "%s %s HTTP/1.0\r\n", Method, waisState->url);
    if (waisState->request_hdr) {
	Packer p;
	packerToMemInit(&p, &mb);
	httpHeaderPackInto(waisState->request_hdr, &p);
	packerClean(&p);
    }
    memBufPrintf(&mb, "\r\n");
    debug(24, 6) ("waisSendRequest: buf: %s\n", mb.buf);
    comm_write_mbuf(fd, mb, waisSendComplete, waisState);
    if (EBIT_TEST(waisState->entry->flags, ENTRY_CACHABLE))
	storeSetPublicKey(waisState->entry);	/* Make it public */
    EBIT_CLR(waisState->entry->flags, ENTRY_FWD_HDR_WAIT);
}

CBDATA_TYPE(WaisStateData);
void
waisStart(FwdState * fwd)
{
    WaisStateData *waisState = NULL;
    request_t *request = fwd->request;
    StoreEntry *entry = fwd->entry;
    int fd = fwd->server_fd;
    const char *url = storeUrl(entry);
    method_t method = request->method;
    debug(24, 3) ("waisStart: \"%s %s\"\n", RequestMethodStr[method], url);
    statCounter.server.all.requests++;
    statCounter.server.other.requests++;
    CBDATA_INIT_TYPE(WaisStateData);
    waisState = cbdataAlloc(WaisStateData);
    waisState->method = method;
    waisState->request_hdr = &request->header;
    waisState->fd = fd;
    waisState->entry = entry;
    xstrncpy(waisState->url, url, MAX_URL);
    waisState->request = requestLink(request);
    waisState->fwd = fwd;
    comm_add_close_handler(waisState->fd, waisStateFree, waisState);
    storeLockObject(entry);
    commSetSelect(fd, COMM_SELECT_WRITE, waisSendRequest, waisState, 0);
    commSetTimeout(fd, Config.Timeout.read, waisTimeout, waisState);
}
