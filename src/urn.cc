
/*
 * DEBUG: section 51    URN Parsing
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

static STCB urnHandleReply;
static wordlist *urn_parsebuffer(const char *inbuf);
static const char *const crlf = "\r\n";
static char *urnConstructMenu(clientHttpRequest * http);

wordlist *
urnFindMinRtt(wordlist * urls, method_t m, int *rtt_ret)
{
    int min_rtt = 0;
    request_t *r;
    int rtt;
    wordlist *w;
    wordlist *min_w = NULL;
    debug(50, 1) ("urnFindMinRtt\n");
    assert(urls != NULL);
    for (w = urls; w; w = w->next) {
	r = urlParse(m, w->key);
	if (r == NULL)
	    continue;
	debug(50, 1) ("Parsed %s\n", w->key);
	rtt = netdbHostRtt(r->host);
	if (rtt == 0) {
	    debug(50, 1) ("Pinging %s\n", r->host);
	    netdbPingSite(r->host);
	    put_free_request_t(r);
	    continue;
	}
	debug(0, 0) ("%s rtt=%d\n", r->host, rtt);
	if (rtt == 0)
		continue;
	if (rtt > min_rtt && min_rtt != 0)
		continue;
	min_rtt = rtt;
	min_w = w;
	put_free_request_t(r);
    }
    if (rtt_ret)
	*rtt_ret = min_rtt;
    debug(50, 1) ("Returning '%s' RTT %d\n",
	min_w ? min_w->key : "NONE",
	min_rtt);
    return min_w;
}

void
urnStart(clientHttpRequest * http)
{
    LOCAL_ARRAY(char, urlres, 4096);
    StoreEntry *e;
    request_t *r = http->request;
    request_t *urlres_r = NULL;
    const cache_key *k;
    char *t;
    debug(50, 1) ("urnStart\n");
    assert(http != NULL);
    debug(50, 1) ("urnStart: '%s'\n", http->uri);
    t = strchr(r->urlpath, ':');
    if (t == NULL) {
        ErrorState *err = errorCon(ERR_URN_RESOLVE, HTTP_NOT_FOUND);
	err->request = requestLink(http->request);
	err->url = http->uri;
	err->src_addr = http->conn->peer.sin_addr;
	errorAppendEntry(http->entry, err);
	return;
    }
    *t = '\0';
    snprintf(urlres, 4096, "http://%s/uri-res/N2L?%s", r->urlpath, t+1);
    k = storeKeyPublic(urlres, METHOD_GET);
    urlres_r = urlParse(METHOD_GET, urlres);
    urlres_r->headers = xstrdup("Accept: */*\r\n\r\n");
    urlres_r->headers_sz = strlen(urlres_r->headers);
    if ((e = storeGet(k)) == NULL) {
	e = storeCreateEntry(urlres, urlres, 0, METHOD_GET);
	storeClientListAdd(e, http);
	protoDispatch(0, e, urlres_r);
    }
    http->entry = e;
    storeClientCopy(e, 0, 0, 4096, get_free_4k_page(), urnHandleReply, http);
}

static void
urnHandleReply(void *data, char *buf, ssize_t size)
{
    clientHttpRequest *http = data;
    StoreEntry *entry = http->entry;
    char *s = NULL;
    wordlist *urls = NULL;
    debug(50, 1) ("urnHandleReply: Called with size=%d.\n", size);
    if (entry->store_status == STORE_ABORTED) {
	put_free_4k_page(buf);
	return;
    }
    if (size == 0) {
	put_free_4k_page(buf);
	return;
    } else if (size < 0) {
	put_free_4k_page(buf);
	return;
    }
    if (entry->store_status == STORE_PENDING) {
	storeClientCopy(entry,
	    entry->mem_obj->inmem_hi,
	    0,
	    SM_PAGE_SIZE,
	    buf,
	    urnHandleReply,
	    http);
	return;
    }
    /* we know its STORE_OK */
    s = mime_headers_end(buf);
    if (s == NULL) {
	debug(0, 0) ("urnHandleReply: didn't find end-of-headers for %s\n",
	    storeUrl(entry));
	return;
    }
    assert(http->entry->mem_obj);
    assert(http->entry->mem_obj->reply);
    httpParseReplyHeaders(buf, http->entry->mem_obj->reply);
    debug(50, 1) ("mem->reply exists, code=%d.\n",
	http->entry->mem_obj->reply->code);
    if (http->entry->mem_obj->reply->code != 200) {
	debug(50, 1) ("urnHandleReply: failed.\n");
	/* XX - return error message */
	urnTranslateDone(http, NULL);
	return;
    }
    while (isspace(*s))
	s++;
    urls = urn_parsebuffer(s);
    urnTranslateDone(http, urls);
    put_free_4k_page(buf);
}


static wordlist *
urn_parsebuffer(const char *inbuf)
{
    char *buf = xstrdup(inbuf);
    char *token;
    wordlist *u;
    wordlist *head = NULL;
    wordlist **last = &head;
    debug(50, 1) ("urn_parsebuffer\n");
    for (token = strtok(buf, crlf); token; token = strtok(NULL, crlf)) {
	debug(0, 0) ("urn_parsebuffer: got '%s'\n", token);
	u = xmalloc(sizeof(wordlist));
	u->key = xstrdup(token);
	u->next = NULL;
	*last = u;
	last = &u->next;
    }
    return head;
}

void
urnTranslateDone(void *data, wordlist * urls)
{
    clientHttpRequest *http = data;
    request_t *new_request = NULL;
    request_t *old_request = http->request;
    ErrorState *err = NULL;
    wordlist *min_w;
    char *buf;
    debug(50, 1) ("urnTranslateDone\n");
    if ((http->urls = urls) == NULL) {	/* unkown URN error */
	debug(50, 1) ("urnTranslateDone: unknown URN (%s).\n", http->uri);
	http->entry = clientCreateStoreEntry(http, old_request->method, 0);
	err = errorCon(ERR_URN_RESOLVE, HTTP_NOT_FOUND);
	err->request = requestLink(http->request);
	err->url = http->uri;
	err->src_addr = http->conn->peer.sin_addr;
	errorAppendEntry(http->entry, err);
	return;
    }
    min_w = urnFindMinRtt(http->urls, http->request->method, NULL);
    if (min_w != NULL) {
	safe_free(http->uri);
    	http->uri = xstrdup(min_w->key);
    	new_request = urlParse(old_request->method, http->uri);
    	new_request->http_ver = old_request->http_ver;
    	new_request->headers = old_request->headers;
    	new_request->headers_sz = old_request->headers_sz;
    	requestUnlink(http->request);
    	http->request = requestLink(new_request);
    	clientAccessCheck(http);
    } else {
	buf = urnConstructMenu(http);
	storeAppend(http->entry, buf, strlen(buf));
	storeComplete(http->entry);
    }
}

static char *
urnConstructMenu(clientHttpRequest * http)
{
    LOCAL_ARRAY(char, buf, 8192);
    LOCAL_ARRAY(char, line, 256);
    LOCAL_ARRAY(char, content, 4096);
    char *hdr;
    wordlist *w;
    debug(50, 1) ("urnConstructMenu\n");
    memset(buf, '\0', 8192);
    memset(content, '\0', 4096);
    assert(http->urls);
    for (w = http->urls; w; w = w->next) {
	snprintf(line, 256, "<LI><A HREF=\"%s\">%s</A>\n", w->key, w->key);
	strcat(buf, line);
    }
    snprintf(content, 4096,
	"<TITLE>Select URL for %s</TITLE>\n"
	"<H2>Select URL for %s</H2>\n<UL>\n%s</UL>"
	"<HR>\n"
	"<ADDRESS>\n"
	"Generated by %s/%s@%s\n"
	"</ADDRESS>\n",
	http->uri, http->uri, buf, appname, version_string, getMyHostname());
    memset(buf, '\0', 8192);
    hdr = httpReplyHeader(1.0,
	HTTP_OK,
	"text/html",
	strlen(content),
	0,
	squid_curtime);
    snprintf(buf, 8192, "%s\r\n%s",
	hdr,
	content);
    return buf;
}
