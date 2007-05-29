
/*
 * $Id: urn.cc,v 1.107 2007/05/29 13:31:41 amosjeffries Exp $
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
#include "errorpage.h"
#include "StoreClient.h"
#include "Store.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "forward.h"
#include "SquidTime.h"

#define	URN_REQBUF_SZ	4096

class UrnState : public StoreClient
{

public:
    void created (StoreEntry *newEntry);
    void *operator new (size_t byteCount);
    void operator delete (void *address);
    void start (HttpRequest *, StoreEntry *);
    char *getHost (String &urlpath);
    void setUriResFromRequest(HttpRequest *);
    bool RequestNeedsMenu(HttpRequest *r);
    void updateRequestURL(HttpRequest *r, char const *newPath);
    void createUriResRequest (String &uri);

    virtual ~UrnState();


    StoreEntry *entry;
    store_client *sc;
    StoreEntry *urlres_e;
    HttpRequest *request;
    HttpRequest *urlres_r;

    struct
    {

unsigned int force_menu:
        1;
    }

    flags;
    char reqbuf[URN_REQBUF_SZ];
    int reqofs;

private:
    char *urlres;
};

typedef struct
{
    char *url;
    char *host;
    int rtt;

    struct
    {
        int cached;
    }

    flags;
}

url_entry;

static STCB urnHandleReply;
static url_entry *urnParseReply(const char *inbuf, method_t);
static const char *const crlf = "\r\n";
static QS url_entry_sort;

CBDATA_TYPE(UrnState);
void *
UrnState::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (UrnState));
    CBDATA_INIT_TYPE(UrnState);
    return cbdataAlloc(UrnState);

}

void
UrnState::operator delete (void *address)
{
    UrnState * tmp = (UrnState *)address;
    cbdataFree (tmp);
}

UrnState::~UrnState ()
{
    safe_free(urlres);
}

static url_entry *
urnFindMinRtt(url_entry * urls, method_t m, int *rtt_ret)
{
    int min_rtt = 0;
    url_entry *u = NULL;
    url_entry *min_u = NULL;
    int i;
    int urlcnt = 0;
    debugs(52, 3, "urnFindMinRtt");
    assert(urls != NULL);

    for (i = 0; NULL != urls[i].url; i++)
        urlcnt++;

    debugs(53, 3, "urnFindMinRtt: Counted " << i << " URLs");

    if (1 == urlcnt) {
        debugs(52, 3, "urnFindMinRtt: Only one URL - return it!");
        return urls;
    }

    for (i = 0; i < urlcnt; i++) {
        u = &urls[i];
        debugs(52, 3, "urnFindMinRtt: " << u->host << " rtt=" << u->rtt);

        if (u->rtt == 0)
            continue;

        if (u->rtt > min_rtt && min_rtt != 0)
            continue;

        min_rtt = u->rtt;

        min_u = u;
    }

    if (rtt_ret)
        *rtt_ret = min_rtt;

    debugs(52, 1, "urnFindMinRtt: Returning '" <<
                  (min_u ? min_u->url : "NONE") << "' RTT " << 
                  min_rtt  );

    return min_u;
}

char *
UrnState::getHost (String &urlpath)
{
    char * result;
    char const *t;

    if ((t = urlpath.pos(':')) != NULL) {
        urlpath.set(t, '\0');
        result = xstrdup(urlpath.buf());
        urlpath.set(t, ':');
    } else {
        result = xstrdup(urlpath.buf());
    }

    return result;
}

bool
UrnState::RequestNeedsMenu(HttpRequest *r)
{
    return strncasecmp(r->urlpath.buf(), "menu.", 5) == 0;
}

void
UrnState::updateRequestURL(HttpRequest *r, char const *newPath)
{
    char *new_path = xstrdup (newPath);
    r->urlpath = new_path;
    xfree(new_path);
}

void
UrnState::createUriResRequest (String &uri)
{
    LOCAL_ARRAY(char, local_urlres, 4096);
    char *host = getHost (uri);
    snprintf(local_urlres, 4096, "http://%s/uri-res/N2L?urn:%s", host, uri.buf());
    safe_free (host);
    safe_free (urlres);
    urlres = xstrdup (local_urlres);
    urlres_r = HttpRequest::CreateFromUrl(urlres);
}

void
UrnState::setUriResFromRequest(HttpRequest *r)
{
    if (RequestNeedsMenu(r)) {
        updateRequestURL(r, r->urlpath.buf() + 5);
        flags.force_menu = 1;
    }

    createUriResRequest (r->urlpath);

    if (urlres_r == NULL) {
        debugs(52, 3, "urnStart: Bad uri-res URL " << urlres);
        ErrorState *err = errorCon(ERR_URN_RESOLVE, HTTP_NOT_FOUND, r);
        err->url = urlres;
        urlres = NULL;
        errorAppendEntry(entry, err);
        return;
    }

    HTTPMSGLOCK(urlres_r);
    urlres_r->header.putStr(HDR_ACCEPT, "text/plain");
}

void
UrnState::start(HttpRequest * r, StoreEntry * e)
{
    debugs(52, 3, "urnStart: '" << e->url() << "'" );
    entry = e;
    request = HTTPMSGLOCK(r);

    entry->lock()

    ;
    setUriResFromRequest(r);

    if (urlres_r == NULL)
        return;

    StoreEntry::getPublic (this, urlres, METHOD_GET);
}

void
UrnState::created(StoreEntry *newEntry)
{
    urlres_e = newEntry;

    if (urlres_e->isNull()) {
        urlres_e = storeCreateEntry(urlres, urlres, request_flags(), METHOD_GET);
        sc = storeClientListAdd(urlres_e, this);
        FwdState::fwdStart(-1, urlres_e, urlres_r);
    } else {

        urlres_e->lock()

        ;
        sc = storeClientListAdd(urlres_e, this);
    }

    reqofs = 0;
    StoreIOBuffer tempBuffer;
    tempBuffer.offset = reqofs;
    tempBuffer.length = URN_REQBUF_SZ;
    tempBuffer.data = reqbuf;
    storeClientCopy(sc, urlres_e,
                    tempBuffer,
                    urnHandleReply,
                    this);
}

void
urnStart(HttpRequest * r, StoreEntry * e)
{
    UrnState *anUrn = new UrnState();
    anUrn->start (r, e);
}

static int
url_entry_sort(const void *A, const void *B)
{
    const url_entry *u1 = (const url_entry *)A;
    const url_entry *u2 = (const url_entry *)B;

    if (u2->rtt == u1->rtt)
        return 0;
    else if (0 == u1->rtt)
        return 1;
    else if (0 == u2->rtt)
        return -1;
    else
        return u1->rtt - u2->rtt;
}

/* TODO: use the clientStream support for this */
static void
urnHandleReply(void *data, StoreIOBuffer result)
{
    UrnState *urnState = static_cast<UrnState *>(data);
    StoreEntry *e = urnState->entry;
    StoreEntry *urlres_e = urnState->urlres_e;
    char *s = NULL;
    size_t k;
    HttpReply *rep;
    url_entry *urls;
    url_entry *u;
    url_entry *min_u;
    MemBuf *mb = NULL;
    ErrorState *err;
    int i;
    int urlcnt = 0;
    char *buf = urnState->reqbuf;
    StoreIOBuffer tempBuffer;

    debugs(52, 3, "urnHandleReply: Called with size=" << (unsigned int)result.length << ".");

    /* Can't be lower because of the goto's */
    HttpVersion version(1, 0);

    if (EBIT_TEST(urlres_e->flags, ENTRY_ABORTED)) {
        goto error;
    }

    if (result.length == 0) {
        goto error;
    } else if (result.flags.error < 0) {
        goto error;
    }

    /* Update reqofs to point to where in the buffer we'd be */
    urnState->reqofs += result.length;

    /* Handle reqofs being bigger than normal */
    if (urnState->reqofs >= URN_REQBUF_SZ) {
        goto error;
    }

    /* If we haven't received the entire object (urn), copy more */
    if (urlres_e->store_status == STORE_PENDING &&
            urnState->reqofs < URN_REQBUF_SZ) {
        tempBuffer.offset = urnState->reqofs;
        tempBuffer.length = URN_REQBUF_SZ;
        tempBuffer.data = urnState->reqbuf + urnState->reqofs;
        storeClientCopy(urnState->sc, urlres_e,
                        tempBuffer,
                        urnHandleReply,
                        urnState);
        return;
    }

    /* we know its STORE_OK */
    k = headersEnd(buf, urnState->reqofs);

    if (0 == k) {
        debugs(52, 1, "urnHandleReply: didn't find end-of-headers for " << e->url()  );
        goto error;
    }

    s = buf + k;
    assert(urlres_e->getReply());
    rep = new HttpReply;
    rep->parseCharBuf(buf, k);
    debugs(52, 3, "reply exists, code=" << rep->sline.status << ".");

    if (rep->sline.status != HTTP_OK) {
        debugs(52, 3, "urnHandleReply: failed.");
        err = errorCon(ERR_URN_RESOLVE, HTTP_NOT_FOUND, urnState->request);
        err->url = xstrdup(e->url());
        errorAppendEntry(e, err);
        delete rep;
        goto error;
    }

    delete rep;

    while (xisspace(*s))
        s++;

    urls = urnParseReply(s, urnState->request->method);

    for (i = 0; NULL != urls[i].url; i++)
        urlcnt++;

    debugs(53, 3, "urnFindMinRtt: Counted " << i << " URLs");

    if (urls == NULL) {		/* unkown URN error */
        debugs(52, 3, "urnTranslateDone: unknown URN " << e->url()  );
        err = errorCon(ERR_URN_RESOLVE, HTTP_NOT_FOUND, urnState->request);
        err->url = xstrdup(e->url());
        errorAppendEntry(e, err);
        goto error;
    }

    min_u = urnFindMinRtt(urls, urnState->request->method, NULL);
    qsort(urls, urlcnt, sizeof(*urls), url_entry_sort);
    e->buffer();
    mb = new MemBuf;
    mb->init();
    mb->Printf( "<TITLE>Select URL for %s</TITLE>\n"
                "<STYLE type=\"text/css\"><!--BODY{background-color:#ffffff;font-family:verdana,sans-serif}--></STYLE>\n"
                "<H2>Select URL for %s</H2>\n"
                "<TABLE BORDER=\"0\" WIDTH=\"100%%\">\n", e->url(), e->url());

    for (i = 0; i < urlcnt; i++) {
        u = &urls[i];
        debugs(52, 3, "URL {" << u->url << "}");
        mb->Printf(
            "<TR><TD><A HREF=\"%s\">%s</A></TD>", u->url, u->url);

        if (urls[i].rtt > 0)
            mb->Printf(
                "<TD align=\"right\">%4d <it>ms</it></TD>", u->rtt);
        else
            mb->Printf("<TD align=\"right\">Unknown</TD>");

        mb->Printf(
            "<TD>%s</TD></TR>\n", u->flags.cached ? "    [cached]" : " ");
    }

    mb->Printf(
        "</TABLE>"
        "<HR noshade size=\"1px\">\n"
        "<ADDRESS>\n"
        "Generated by %s@%s\n"
        "</ADDRESS>\n",
        full_appname_string, getMyHostname());
    rep = new HttpReply;
    rep->setHeaders(version, HTTP_MOVED_TEMPORARILY, NULL,
                    "text/html", mb->contentSize(), 0, squid_curtime);

    if (urnState->flags.force_menu) {
        debugs(51, 3, "urnHandleReply: forcing menu");
    } else if (min_u) {
        rep->header.putStr(HDR_LOCATION, min_u->url);
    }

    httpBodySet(&rep->body, mb);
    /* don't clean or delete mb; rep->body owns it now */
    e->replaceHttpReply(rep);
    e->complete();

    for (i = 0; i < urlcnt; i++) {
        safe_free(urls[i].url);
        safe_free(urls[i].host);
    }

    safe_free(urls);
    /* mb was absorbed in httpBodySet call, so we must not clean it */
    storeUnregister(urnState->sc, urlres_e, urnState);

error:
    urlres_e->unlock();
    urnState->entry->unlock();
    HTTPMSGUNLOCK(urnState->request);
    HTTPMSGUNLOCK(urnState->urlres_r);
    delete urnState;
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
    debugs(52, 3, "urnParseReply");
    list = (url_entry *)xcalloc(n + 1, sizeof(*list));

    for (token = strtok(buf, crlf); token; token = strtok(NULL, crlf)) {
        debugs(52, 3, "urnParseReply: got '" << token << "'");

        if (i == n) {
            old = list;
            n <<= 2;
            list = (url_entry *)xcalloc(n + 1, sizeof(*list));
            xmemcpy(list, old, i * sizeof(*list));
            safe_free(old);
        }

        url = xstrdup(token);
        host = urlHostname(url);

        if (NULL == host)
            continue;

        rtt = netdbHostRtt(host);

        if (0 == rtt) {
            debugs(52, 3, "urnParseReply: Pinging " << host);
            netdbPingSite(host);
        }

        list[i].url = url;
        list[i].host = xstrdup(host);
        list[i].rtt = rtt;
        list[i].flags.cached = storeGetPublic(url, m) ? 1 : 0;
        i++;
    }

    debugs(52, 3, "urnParseReply: Found " << i << " URLs");
    return list;
}
