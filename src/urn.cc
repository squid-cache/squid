
/*
 * $Id: urn.cc,v 1.71 2002/07/18 23:43:14 hno Exp $
 *
 * DEBUG: section 52    URN Parsing
 * AUTHOR: Kostas Anagnostakis
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

#define	URN_REQBUF_SZ	4096

typedef struct {
    StoreEntry *entry;
    store_client *sc;
    StoreEntry *urlres_e;
    request_t *request;
    request_t *urlres_r;
    struct {
	unsigned int force_menu:1;
    } flags;
    char reqbuf[URN_REQBUF_SZ];
    int reqofs;
} UrnState;

typedef struct {
    char *url;
    char *host;
    int rtt;
    struct {
	int cached;
    } flags;
} url_entry;

static STCB urnHandleReply;
static url_entry *urnParseReply(const char *inbuf, method_t);
static const char *const crlf = "\r\n";
static QS url_entry_sort;

static url_entry *
urnFindMinRtt(url_entry * urls, method_t m, int *rtt_ret)
{
    int min_rtt = 0;
    url_entry *u = NULL;
    url_entry *min_u = NULL;
    int i;
    int urlcnt = 0;
    debug(52, 3) ("urnFindMinRtt\n");
    assert(urls != NULL);
    for (i = 0; NULL != urls[i].url; i++)
	urlcnt++;
    debug(53, 3) ("urnFindMinRtt: Counted %d URLs\n", i);
    if (1 == urlcnt) {
	debug(52, 3) ("urnFindMinRtt: Only one URL - return it!\n");
	return urls;
    }
    for (i = 0; i < urlcnt; i++) {
	u = &urls[i];
	debug(52, 3) ("urnFindMinRtt: %s rtt=%d\n", u->host, u->rtt);
	if (u->rtt == 0)
	    continue;
	if (u->rtt > min_rtt && min_rtt != 0)
	    continue;
	min_rtt = u->rtt;
	min_u = u;
    }
    if (rtt_ret)
	*rtt_ret = min_rtt;
    debug(52, 1) ("urnFindMinRtt: Returning '%s' RTT %d\n",
	min_u ? min_u->url : "NONE",
	min_rtt);
    return min_u;
}

CBDATA_TYPE(UrnState);
void
urnStart(request_t * r, StoreEntry * e)
{
    LOCAL_ARRAY(char, urlres, 4096);
    request_t *urlres_r = NULL;
    const char *t;
    char *host;
    UrnState *urnState;
    StoreEntry *urlres_e;
    ErrorState *err;
    debug(52, 3) ("urnStart: '%s'\n", storeUrl(e));
    CBDATA_INIT_TYPE(UrnState);
    urnState = cbdataAlloc(UrnState);
    urnState->entry = e;
    urnState->request = requestLink(r);
    storeLockObject(urnState->entry);
    if (strncasecmp(strBuf(r->urlpath), "menu.", 5) == 0) {
	char *new_path = xstrdup(strBuf(r->urlpath) + 5);
	urnState->flags.force_menu = 1;
	stringReset(&r->urlpath, new_path);
	xfree(new_path);
    }
    if ((t = strChr(r->urlpath, ':')) != NULL) {
	strSet(r->urlpath, t, '\0');
	host = xstrdup(strBuf(r->urlpath));
	strSet(r->urlpath, t, ':');
    } else {
	host = xstrdup(strBuf(r->urlpath));
    }
    snprintf(urlres, 4096, "http://%s/uri-res/N2L?urn:%s", host, strBuf(r->urlpath));
    safe_free(host);
    urlres_r = urlParse(METHOD_GET, urlres);
    if (urlres_r == NULL) {
	debug(52, 3) ("urnStart: Bad uri-res URL %s\n", urlres);
	err = errorCon(ERR_URN_RESOLVE, HTTP_NOT_FOUND);
	err->url = xstrdup(urlres);
	errorAppendEntry(e, err);
	return;
    }
    httpHeaderPutStr(&urlres_r->header, HDR_ACCEPT, "text/plain");
    if ((urlres_e = storeGetPublic(urlres, METHOD_GET)) == NULL) {
	urlres_e = storeCreateEntry(urlres, urlres, null_request_flags, METHOD_GET);
	urnState->sc = storeClientListAdd(urlres_e, urnState);
	fwdStart(-1, urlres_e, urlres_r);
    } else {
	storeLockObject(urlres_e);
	urnState->sc = storeClientListAdd(urlres_e, urnState);
    }
    urnState->urlres_e = urlres_e;
    urnState->urlres_r = requestLink(urlres_r);
    urnState->reqofs = 0;
    storeClientCopy(urnState->sc, urlres_e,
	0,
	URN_REQBUF_SZ,
	urnState->reqbuf,
	urnHandleReply,
	urnState);
}

static int
url_entry_sort(const void *A, const void *B)
{
    const url_entry *u1 = A;
    const url_entry *u2 = B;
    if (u2->rtt == u1->rtt)
	return 0;
    else if (0 == u1->rtt)
	return 1;
    else if (0 == u2->rtt)
	return -1;
    else
	return u1->rtt - u2->rtt;
}

static void
urnHandleReply(void *data, char *unused_buf, ssize_t size)
{
    UrnState *urnState = data;
    StoreEntry *e = urnState->entry;
    StoreEntry *urlres_e = urnState->urlres_e;
    char *s = NULL;
    size_t k;
    HttpReply *rep;
    url_entry *urls;
    url_entry *u;
    url_entry *min_u;
    MemBuf mb;
    ErrorState *err;
    int i;
    int urlcnt = 0;
    http_version_t version;
    char *buf = urnState->reqbuf;

    debug(52, 3) ("urnHandleReply: Called with size=%d.\n", (int) size);
    if (EBIT_TEST(urlres_e->flags, ENTRY_ABORTED)) {
	goto error;
    }
    if (size == 0) {
	goto error;
    } else if (size < 0) {
	goto error;
    }
    /* Update reqofs to point to where in the buffer we'd be */
    urnState->reqofs += size;

    /* Handle reqofs being bigger than normal */
    if (urnState->reqofs >= URN_REQBUF_SZ) {
	goto error;
    }
    /* If we haven't received the entire object (urn), copy more */
    if (urlres_e->store_status == STORE_PENDING &&
	urnState->reqofs < URN_REQBUF_SZ) {
	storeClientCopy(urnState->sc, urlres_e,
	    urnState->reqofs,
	    URN_REQBUF_SZ,
	    urnState->reqbuf + urnState->reqofs,
	    urnHandleReply,
	    urnState);
	return;
    }
    /* we know its STORE_OK */
    k = headersEnd(buf, urnState->reqofs);
    if (0 == k) {
	debug(52, 1) ("urnHandleReply: didn't find end-of-headers for %s\n",
	    storeUrl(e));
	goto error;
    }
    s = buf + k;
    assert(urlres_e->mem_obj->reply);
    httpReplyParse(urlres_e->mem_obj->reply, buf, k);
    debug(52, 3) ("mem->reply exists, code=%d.\n",
	urlres_e->mem_obj->reply->sline.status);
    if (urlres_e->mem_obj->reply->sline.status != HTTP_OK) {
	debug(52, 3) ("urnHandleReply: failed.\n");
	err = errorCon(ERR_URN_RESOLVE, HTTP_NOT_FOUND);
	err->request = requestLink(urnState->request);
	err->url = xstrdup(storeUrl(e));
	errorAppendEntry(e, err);
	goto error;
    }
    while (xisspace(*s))
	s++;
    urls = urnParseReply(s, urnState->request->method);
    for (i = 0; NULL != urls[i].url; i++)
	urlcnt++;
    debug(53, 3) ("urnFindMinRtt: Counted %d URLs\n", i);
    if (urls == NULL) {		/* unkown URN error */
	debug(52, 3) ("urnTranslateDone: unknown URN %s\n", storeUrl(e));
	err = errorCon(ERR_URN_RESOLVE, HTTP_NOT_FOUND);
	err->request = requestLink(urnState->request);
	err->url = xstrdup(storeUrl(e));
	errorAppendEntry(e, err);
	goto error;
    }
    min_u = urnFindMinRtt(urls, urnState->request->method, NULL);
    qsort(urls, urlcnt, sizeof(*urls), url_entry_sort);
    storeBuffer(e);
    memBufDefInit(&mb);
    memBufPrintf(&mb,
	"<TITLE>Select URL for %s</TITLE>\n"
	"<STYLE type= \"text/css\"><!--BODY{background-color:#ffffff; font-family:verdana,sans-serif}--></STYLE>\n"
	"<H2>Select URL for %s</H2>\n"
	"<TABLE BORDER=\"0\" WIDTH=\"100%%\">\n", storeUrl(e), storeUrl(e));
    for (i = 0; i < urlcnt; i++) {
	u = &urls[i];
	debug(52, 3) ("URL {%s}\n", u->url);
	memBufPrintf(&mb,
	    "<TR><TD><A HREF=\"%s\">%s</A></TD>", u->url, u->url);
	if (urls[i].rtt > 0)
	    memBufPrintf(&mb,
		"<TD align=\"right\">%4d </it>ms</it></TD>", u->rtt);
	else
	    memBufPrintf(&mb, "<TD align=\"right\">Unknown</TD>");
	memBufPrintf(&mb,
	    "<TD>%s</TD></TR>\n", u->flags.cached ? "    [cached]" : " ");
    }
    memBufPrintf(&mb,
	"</TABLE>"
	"<HR noshade size=\"1px\">\n"
	"<ADDRESS>\n"
	"Generated by %s@%s\n"
	"</ADDRESS>\n",
	full_appname_string, getMyHostname());
    rep = e->mem_obj->reply;
    httpReplyReset(rep);
    httpBuildVersion(&version, 1, 0);
    httpReplySetHeaders(rep, version, HTTP_MOVED_TEMPORARILY, NULL,
	"text/html", mb.size, 0, squid_curtime);
    if (urnState->flags.force_menu) {
	debug(51, 3) ("urnHandleReply: forcing menu\n");
    } else if (min_u) {
	httpHeaderPutStr(&rep->header, HDR_LOCATION, min_u->url);
    }
    httpBodySet(&rep->body, &mb);
    httpReplySwapOut(rep, e);
    storeComplete(e);
    for (i = 0; i < urlcnt; i++) {
	safe_free(urls[i].url);
	safe_free(urls[i].host);
    }
    safe_free(urls);
    /* mb was absorbed in httpBodySet call, so we must not clean it */
    storeUnregister(urnState->sc, urlres_e, urnState);
  error:
    storeUnlockObject(urlres_e);
    storeUnlockObject(urnState->entry);
    requestUnlink(urnState->request);
    requestUnlink(urnState->urlres_r);
    cbdataFree(urnState);
}

static url_entry *
urnParseReply(const char *inbuf, method_t m)
{
    char *buf = xstrdup(inbuf);
    char *token;
    char *url;
    char *host;
    int rtt;
    url_entry *list;
    url_entry *old;
    int n = 32;
    int i = 0;
    debug(52, 3) ("urnParseReply\n");
    list = xcalloc(n + 1, sizeof(*list));
    for (token = strtok(buf, crlf); token; token = strtok(NULL, crlf)) {
	debug(52, 3) ("urnParseReply: got '%s'\n", token);
	if (i == n) {
	    old = list;
	    n <<= 2;
	    list = xcalloc(n + 1, sizeof(*list));
	    xmemcpy(list, old, i * sizeof(*list));
	    safe_free(old);
	}
	url = xstrdup(token);
	host = urlHostname(url);
	if (NULL == host)
	    continue;
	rtt = netdbHostRtt(host);
	if (0 == rtt) {
	    debug(52, 3) ("urnParseReply: Pinging %s\n", host);
	    netdbPingSite(host);
	}
	list[i].url = url;
	list[i].host = xstrdup(host);
	list[i].rtt = rtt;
	list[i].flags.cached = storeGetPublic(url, m) ? 1 : 0;
	i++;
    }
    debug(52, 3) ("urnParseReply: Found %d URLs\n", i);
    return list;
}
