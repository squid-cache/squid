
/*
 *
 * $Id: urn.cc,v 1.37 1998/07/14 06:13:01 wessels Exp $
 *
 * DEBUG: section 52    URN Parsing
 * AUTHOR: Kostas Anagnostakis
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

enum {
    URN_FORCE_MENU
};

typedef struct {
    StoreEntry *entry;
    StoreEntry *urlres_e;
    request_t *request;
    request_t *urlres_r;
    int flags;
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

url_entry *
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
    debug(0, 0) ("urnFindMinRtt: Counted %d URLs\n", i);
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

void
urnStart(request_t * r, StoreEntry * e)
{
    LOCAL_ARRAY(char, urlres, 4096);
    request_t *urlres_r = NULL;
    const cache_key *k;
    const char *t;
    char *host;
    UrnState *urnState;
    StoreEntry *urlres_e;
    ErrorState *err;
    debug(52, 3) ("urnStart: '%s'\n", storeUrl(e));
    urnState = xcalloc(1, sizeof(UrnState));
    urnState->entry = e;
    urnState->request = requestLink(r);
    cbdataAdd(urnState, MEM_NONE);
    storeLockObject(urnState->entry);
    if (strncasecmp(strBuf(r->urlpath), "menu.", 5) == 0) {
	char *new_path = xstrdup(strBuf(r->urlpath) + 5);
	EBIT_SET(urnState->flags, URN_FORCE_MENU);
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
    k = storeKeyPublic(urlres, METHOD_GET);
    urlres_r = urlParse(METHOD_GET, urlres);
    if (urlres_r == NULL) {
	debug(52, 3) ("urnStart: Bad uri-res URL %s\n", urlres);
	err = errorCon(ERR_URN_RESOLVE, HTTP_NOT_FOUND);
	err->url = xstrdup(urlres);
	errorAppendEntry(e, err);
	return;
    }
#if OLD_CODE
    urlres_r->headers = xstrdup("Accept: text/plain\r\n\r\n");
    urlres_r->headers_sz = strlen(urlres_r->headers);
#else
    httpHeaderPutStr(&urlres_r->header, HDR_ACCEPT, "text/plain");
#endif
    if ((urlres_e = storeGet(k)) == NULL) {
	urlres_e = storeCreateEntry(urlres, urlres, 0, METHOD_GET);
	storeClientListAdd(urlres_e, urnState);
	fwdStart(-1, urlres_e, urlres_r, any_addr);
    } else {
	storeLockObject(urlres_e);
	storeClientListAdd(urlres_e, urnState);
    }
    urnState->urlres_e = urlres_e;
    urnState->urlres_r = requestLink(urlres_r);
    storeClientCopy(urlres_e,
	0,
	0,
	4096,
	memAllocate(MEM_4K_BUF),
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
urnHandleReply(void *data, char *buf, ssize_t size)
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

    debug(52, 3) ("urnHandleReply: Called with size=%d.\n", size);
    if (urlres_e->store_status == STORE_ABORTED) {
	memFree(MEM_4K_BUF, buf);
	return;
    }
    if (size == 0) {
	memFree(MEM_4K_BUF, buf);
	return;
    } else if (size < 0) {
	memFree(MEM_4K_BUF, buf);
	return;
    }
    if (urlres_e->store_status == STORE_PENDING && size < SM_PAGE_SIZE) {
	storeClientCopy(urlres_e,
	    size,
	    0,
	    SM_PAGE_SIZE,
	    buf,
	    urnHandleReply,
	    urnState);
	return;
    }
    /* we know its STORE_OK */
    k = headersEnd(buf, size);
    if (0 == k) {
	debug(52, 1) ("urnHandleReply: didn't find end-of-headers for %s\n",
	    storeUrl(e));
	return;
    }
    s = buf + k;
    assert(urlres_e->mem_obj->reply);
    httpReplyParse(urlres_e->mem_obj->reply, buf);
    debug(52, 3) ("mem->reply exists, code=%d.\n",
	urlres_e->mem_obj->reply->sline.status);
    if (urlres_e->mem_obj->reply->sline.status != HTTP_OK) {
	debug(52, 3) ("urnHandleReply: failed.\n");
	err = errorCon(ERR_URN_RESOLVE, HTTP_NOT_FOUND);
	err->request = requestLink(urnState->request);
	err->url = xstrdup(storeUrl(e));
	errorAppendEntry(e, err);
	return;
    }
    while (isspace(*s))
	s++;
    urls = urnParseReply(s, urnState->request->method);
    for (i = 0; NULL != urls[i].url; i++)
	urlcnt++;
    debug(0, 0) ("urnFindMinRtt: Counted %d URLs\n", i);
    if (urls == NULL) {		/* unkown URN error */
	debug(52, 3) ("urnTranslateDone: unknown URN %s\n", storeUrl(e));
	err = errorCon(ERR_URN_RESOLVE, HTTP_NOT_FOUND);
	err->request = requestLink(urnState->request);
	err->url = xstrdup(storeUrl(e));
	errorAppendEntry(e, err);
	return;
    }
    min_u = urnFindMinRtt(urls, urnState->request->method, NULL);
    qsort(urls, urlcnt, sizeof(*urls), url_entry_sort);
    storeBuffer(e);
    memBufDefInit(&mb);
    memBufPrintf(&mb,
	"<TITLE>Select URL for %s</TITLE>\n"
	"<H2>Select URL for %s</H2>\n"
	"<TABLE BORDER=0 WIDTH=\"100%%\">\n", storeUrl(e), storeUrl(e));
    for (i = 0; i < urlcnt; i++) {
	u = &urls[i];
	debug(0, 0) ("URL {%s}\n", u->url);
	memBufPrintf(&mb,
	    "<TR><TD><A HREF=\"%s\">%s</A></TD>", u->url, u->url);
	if (urls[i].rtt > 0)
	    memBufPrintf(&mb,
		"<TD align=right>%4d </it>ms</it></TD>", u->rtt);
	else
	    memBufPrintf(&mb, "<TD align=right>Unknown</TD>");
	memBufPrintf(&mb,
	    "<TD>%s</TD></TR>\n", u->flags.cached ? "    [cached]" : " ");
    }
    memBufPrintf(&mb,
	"</TABLE>"
	"<HR>\n"
	"<ADDRESS>\n"
	"Generated by %s@%s\n"
	"</ADDRESS>\n",
	full_appname_string, getMyHostname());
    rep = e->mem_obj->reply;
    httpReplyReset(rep);
    httpReplySetHeaders(rep, 1.0, HTTP_MOVED_TEMPORARILY, NULL,
	"text/html", mb.size, 0, squid_curtime);
    if (EBIT_TEST(urnState->flags, URN_FORCE_MENU)) {
	debug(51, 3) ("urnHandleReply: forcing menu\n");
    } else if (min_u) {
	httpHeaderPutStr(&rep->header, HDR_LOCATION, min_u->url);
    }
    httpBodySet(&rep->body, &mb);
    httpReplySwapOut(rep, e);
    storeComplete(e);
    memFree(MEM_4K_BUF, buf);
    for (i = 0; i < urlcnt; i++) {
	safe_free(urls[i].url);
	safe_free(urls[i].host);
    }
    safe_free(urls);
    /* mb was absorbed in httpBodySet call, so we must not clean it */
    storeUnregister(urlres_e, urnState);
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
    const cache_key *key;
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
	key = storeKeyPublic(url, m);
	list[i].url = url;
	list[i].host = xstrdup(host);
	list[i].rtt = rtt;
	list[i].flags.cached = storeGet(key) ? 1 : 0;
	i++;
    }
    debug(0, 0) ("urnParseReply: Found %d URLs\n", i);
    return list;
}
