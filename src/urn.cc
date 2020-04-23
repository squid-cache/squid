/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 52    URN Parsing */

#include "squid.h"
#include "AccessLogEntry.h"
#include "acl/FilledChecklist.h"
#include "base/TextException.h"
#include "cbdata.h"
#include "errorpage.h"
#include "FwdState.h"
#include "globals.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "icmp/net_db.h"
#include "MemBuf.h"
#include "mime_header.h"
#include "RequestFlags.h"
#include "SquidTime.h"
#include "Store.h"
#include "StoreClient.h"
#include "tools.h"
#include "urn.h"

#define URN_REQBUF_SZ   4096

class UrnState : public StoreClient
{
    CBDATA_CLASS(UrnState);

public:
    explicit UrnState(const AccessLogEntry::Pointer &anAle): ale(anAle) {}

    void created (StoreEntry *newEntry);
    void start (HttpRequest *, StoreEntry *);
    void setUriResFromRequest(HttpRequest *);

    virtual ~UrnState();

    StoreEntry *entry = nullptr;
    store_client *sc = nullptr;
    StoreEntry *urlres_e = nullptr;
    HttpRequest::Pointer request;
    HttpRequest::Pointer urlres_r;
    AccessLogEntry::Pointer ale; ///< details of the requesting transaction

    char reqbuf[URN_REQBUF_SZ] = { '\0' };
    int reqofs = 0;

private:
    /* StoreClient API */
    virtual LogTags *loggingTags() { return ale ? &ale->cache.code : nullptr; }
    virtual void fillChecklist(ACLFilledChecklist &) const;

    char *urlres = nullptr;
};

typedef struct {
    char *url;
    char *host;
    int rtt;

    struct {
        int cached;
    } flags;
} url_entry;

static STCB urnHandleReply;
static url_entry *urnParseReply(const char *inbuf, const HttpRequestMethod&);
static const char *const crlf = "\r\n";

CBDATA_CLASS_INIT(UrnState);

UrnState::~UrnState()
{
    SWALLOW_EXCEPTIONS({
        if (urlres_e) {
            if (sc)
                storeUnregister(sc, urlres_e, this);
            urlres_e->unlock("~UrnState+res");
        }

        if (entry)
            entry->unlock("~UrnState+prime");

        safe_free(urlres);
    });
}

static url_entry *
urnFindMinRtt(url_entry * urls, const HttpRequestMethod &, int *rtt_ret)
{
    int min_rtt = 0;
    url_entry *u = NULL;
    url_entry *min_u = NULL;
    int i;
    int urlcnt = 0;
    debugs(52, 3, "urnFindMinRtt");
    assert(urls != NULL);

    for (i = 0; NULL != urls[i].url; ++i)
        ++urlcnt;

    debugs(53, 3, "urnFindMinRtt: Counted " << i << " URLs");

    if (1 == urlcnt) {
        debugs(52, 3, "urnFindMinRtt: Only one URL - return it!");
        return urls;
    }

    for (i = 0; i < urlcnt; ++i) {
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

    debugs(52, DBG_IMPORTANT, "urnFindMinRtt: Returning '" <<
           (min_u ? min_u->url : "NONE") << "' RTT " <<
           min_rtt  );

    return min_u;
}

void
UrnState::setUriResFromRequest(HttpRequest *r)
{
    const auto &query = r->url.absolute();
    const auto host = r->url.host();
    // TODO: use class AnyP::Uri instead of generating a string and re-parsing
    LOCAL_ARRAY(char, local_urlres, 4096);
    snprintf(local_urlres, 4096, "http://%s/uri-res/N2L?" SQUIDSBUFPH, host, SQUIDSBUFPRINT(query));
    safe_free(urlres);
    urlres_r = HttpRequest::FromUrlXXX(local_urlres, r->masterXaction);

    if (!urlres_r) {
        debugs(52, 3, "Bad uri-res URL " << local_urlres);
        const auto err = new ErrorState(ERR_URN_RESOLVE, Http::scNotFound, r, ale);
        err->url = xstrdup(local_urlres);
        errorAppendEntry(entry, err);
        return;
    }

    urlres = xstrdup(local_urlres);
    urlres_r->header.putStr(Http::HdrType::ACCEPT, "text/plain");
}

void
UrnState::start(HttpRequest * r, StoreEntry * e)
{
    debugs(52, 3, "urnStart: '" << e->url() << "'" );
    entry = e;
    request = r;

    entry->lock("UrnState::start");
    setUriResFromRequest(r);

    if (urlres_r == NULL)
        return;

    StoreEntry::getPublic (this, urlres, Http::METHOD_GET);
}

void
UrnState::fillChecklist(ACLFilledChecklist &checklist) const
{
    checklist.setRequest(request.getRaw());
    checklist.al = ale;
}

void
UrnState::created(StoreEntry *e)
{
    if (!e || (e->hittingRequiresCollapsing() && !startCollapsingOn(*e, false))) {
        urlres_e = storeCreateEntry(urlres, urlres, RequestFlags(), Http::METHOD_GET);
        sc = storeClientListAdd(urlres_e, this);
        FwdState::Start(Comm::ConnectionPointer(), urlres_e, urlres_r.getRaw(), ale);
        // TODO: StoreClients must either store/lock or abandon found entries.
        //if (e)
        //    e->abandon();
    } else {
        urlres_e = e;
        urlres_e->lock("UrnState::created");
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
urnStart(HttpRequest *r, StoreEntry *e, const AccessLogEntryPointer &ale)
{
    const auto anUrn = new UrnState(ale);
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
    ErrorState *err;
    int i;
    int urlcnt = 0;
    char *buf = urnState->reqbuf;
    StoreIOBuffer tempBuffer;

    debugs(52, 3, "urnHandleReply: Called with size=" << result.length << ".");

    if (EBIT_TEST(urlres_e->flags, ENTRY_ABORTED) || result.flags.error) {
        delete urnState;
        return;
    }

    /* Update reqofs to point to where in the buffer we'd be */
    urnState->reqofs += result.length;

    /* Handle reqofs being bigger than normal */
    if (urnState->reqofs >= URN_REQBUF_SZ) {
        delete urnState;
        return;
    }

    /* If we haven't received the entire object (urn), copy more */
    if (urlres_e->store_status == STORE_PENDING) {
        Must(result.length > 0); // zero length ought to imply STORE_OK
        tempBuffer.offset = urnState->reqofs;
        tempBuffer.length = URN_REQBUF_SZ - urnState->reqofs;
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
        debugs(52, DBG_IMPORTANT, "urnHandleReply: didn't find end-of-headers for " << e->url()  );
        delete urnState;
        return;
    }

    s = buf + k;
    // TODO: Check whether we should parse urlres_e reply, as before 528b2c61.
    rep = new HttpReply;
    rep->parseCharBuf(buf, k);
    debugs(52, 3, "reply exists, code=" << rep->sline.status() << ".");

    if (rep->sline.status() != Http::scOkay) {
        debugs(52, 3, "urnHandleReply: failed.");
        err = new ErrorState(ERR_URN_RESOLVE, Http::scNotFound, urnState->request.getRaw(), urnState->ale);
        err->url = xstrdup(e->url());
        errorAppendEntry(e, err);
        delete rep;
        delete urnState;
        return;
    }

    delete rep;

    while (xisspace(*s))
        ++s;

    urls = urnParseReply(s, urnState->request->method);

    if (!urls) {     /* unknown URN error */
        debugs(52, 3, "urnTranslateDone: unknown URN " << e->url());
        err = new ErrorState(ERR_URN_RESOLVE, Http::scNotFound, urnState->request.getRaw(), urnState->ale);
        err->url = xstrdup(e->url());
        errorAppendEntry(e, err);
        delete urnState;
        return;
    }

    for (i = 0; urls[i].url; ++i)
        ++urlcnt;

    debugs(53, 3, "urnFindMinRtt: Counted " << i << " URLs");

    min_u = urnFindMinRtt(urls, urnState->request->method, NULL);
    qsort(urls, urlcnt, sizeof(*urls), url_entry_sort);
    e->buffer();
    SBuf body;
    SBuf *mb = &body; // diff reduction hack; TODO: Remove
    mb->appendf( "<TITLE>Select URL for %s</TITLE>\n"
                 "<STYLE type=\"text/css\"><!--BODY{background-color:#ffffff;font-family:verdana,sans-serif}--></STYLE>\n"
                 "<H2>Select URL for %s</H2>\n"
                 "<TABLE BORDER=\"0\" WIDTH=\"100%%\">\n", e->url(), e->url());

    for (i = 0; i < urlcnt; ++i) {
        u = &urls[i];
        debugs(52, 3, "URL {" << u->url << "}");
        mb->appendf(
            "<TR><TD><A HREF=\"%s\">%s</A></TD>", u->url, u->url);

        if (urls[i].rtt > 0)
            mb->appendf(
                "<TD align=\"right\">%4d <it>ms</it></TD>", u->rtt);
        else
            mb->appendf("<TD align=\"right\">Unknown</TD>");

        mb->appendf("<TD>%s</TD></TR>\n", u->flags.cached ? "    [cached]" : " ");
    }

    mb->appendf(
        "</TABLE>"
        "<HR noshade size=\"1px\">\n"
        "<ADDRESS>\n"
        "Generated by %s@%s\n"
        "</ADDRESS>\n",
        APP_FULLNAME, getMyHostname());
    rep = new HttpReply;
    rep->setHeaders(Http::scFound, NULL, "text/html", mb->length(), 0, squid_curtime);

    if (min_u) {
        rep->header.putStr(Http::HdrType::LOCATION, min_u->url);
    }

    rep->body.set(body);
    e->replaceHttpReply(rep);
    e->complete();

    for (i = 0; i < urlcnt; ++i) {
        safe_free(urls[i].url);
        safe_free(urls[i].host);
    }

    safe_free(urls);

    delete urnState;
}

static url_entry *
urnParseReply(const char *inbuf, const HttpRequestMethod& m)
{
    char *buf = xstrdup(inbuf);
    char *token;
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
            memcpy(list, old, i * sizeof(*list));
            safe_free(old);
        }

        AnyP::Uri uri;
        if (!uri.parse(m, SBuf(token)) || !*uri.host())
            continue;

#if USE_ICMP
        list[i].rtt = netdbHostRtt(uri.host());

        if (0 == list[i].rtt) {
            debugs(52, 3, "Pinging " << uri.host());
            netdbPingSite(uri.host());
        }
#else
        list[i].rtt = 0;
#endif

        list[i].url = xstrdup(uri.absolute().c_str());
        list[i].host = xstrdup(uri.host());
        // TODO: Use storeHas() or lock/unlock entry to avoid creating unlocked
        // ones.
        list[i].flags.cached = storeGetPublic(list[i].url, m) ? 1 : 0;
        ++i;
    }

    debugs(52, 3, "urnParseReply: Found " << i << " URLs");
    return list;
}

