/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 73    HTTP Request */

#include "squid.h"
#include "AccessLogEntry.h"
#include "acl/AclSizeLimit.h"
#include "acl/FilledChecklist.h"
#include "CachePeer.h"
#include "client_side.h"
#include "client_side_request.h"
#include "dns/LookupDetails.h"
#include "Downloader.h"
#include "error/Detail.h"
#include "globals.h"
#include "gopher.h"
#include "http.h"
#include "http/ContentLengthInterpreter.h"
#include "http/one/RequestParser.h"
#include "http/Stream.h"
#include "HttpHdrCc.h"
#include "HttpHeaderRange.h"
#include "HttpRequest.h"
#include "log/Config.h"
#include "MemBuf.h"
#include "sbuf/StringConvert.h"
#include "SquidConfig.h"
#include "Store.h"

#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if ICAP_CLIENT
#include "adaptation/icap/icap_log.h"
#endif

HttpRequest::HttpRequest(const MasterXaction::Pointer &mx) :
    Http::Message(hoRequest),
    masterXaction(mx)
{
    assert(mx);
    init();
}

HttpRequest::HttpRequest(const HttpRequestMethod& aMethod, AnyP::ProtocolType aProtocol, const char *aSchemeImg, const char *aUrlpath, const MasterXaction::Pointer &mx) :
    Http::Message(hoRequest),
    masterXaction(mx)
{
    assert(mx);
    static unsigned int id = 1;
    debugs(93,7, HERE << "constructed, this=" << this << " id=" << ++id);
    init();
    initHTTP(aMethod, aProtocol, aSchemeImg, aUrlpath);
}

HttpRequest::~HttpRequest()
{
    clean();
    debugs(93,7, HERE << "destructed, this=" << this);
}

void
HttpRequest::initHTTP(const HttpRequestMethod& aMethod, AnyP::ProtocolType aProtocol, const char *aSchemeImg, const char *aUrlpath)
{
    method = aMethod;
    url.setScheme(aProtocol, aSchemeImg);
    url.path(aUrlpath);
}

void
HttpRequest::init()
{
    method = Http::METHOD_NONE;
    url.clear();
#if USE_AUTH
    auth_user_request = NULL;
#endif
    flags = RequestFlags();
    range = NULL;
    ims = -1;
    imslen = 0;
    lastmod = -1;
    client_addr.setEmpty();
    my_addr.setEmpty();
    body_pipe = NULL;
    // hier
    dnsWait = -1;
    error.clear();
    peer_login = NULL;      // not allocated/deallocated by this class
    peer_domain = NULL;     // not allocated/deallocated by this class
    peer_host = NULL;
    vary_headers = SBuf();
    myportname = null_string;
    tag = null_string;
#if USE_AUTH
    extacl_user = null_string;
    extacl_passwd = null_string;
#endif
    extacl_log = null_string;
    extacl_message = null_string;
    pstate = Http::Message::psReadyToParseStartLine;
#if FOLLOW_X_FORWARDED_FOR
    indirect_client_addr.setEmpty();
#endif /* FOLLOW_X_FORWARDED_FOR */
#if USE_ADAPTATION
    adaptHistory_ = NULL;
#endif
#if ICAP_CLIENT
    icapHistory_ = NULL;
#endif
    rangeOffsetLimit = -2; //a value of -2 means not checked yet
    forcedBodyContinuation = false;
}

void
HttpRequest::clean()
{
    // we used to assert that the pipe is NULL, but now the request only
    // points to a pipe that is owned and initiated by another object.
    body_pipe = NULL;
#if USE_AUTH
    auth_user_request = NULL;
#endif
    vary_headers.clear();
    url.clear();

    header.clean();

    if (cache_control) {
        delete cache_control;
        cache_control = NULL;
    }

    if (range) {
        delete range;
        range = NULL;
    }

    myportname.clean();

    theNotes = nullptr;

    tag.clean();
#if USE_AUTH
    extacl_user.clean();
    extacl_passwd.clean();
#endif
    extacl_log.clean();

    extacl_message.clean();

    etag.clean();

#if USE_ADAPTATION
    adaptHistory_ = NULL;
#endif
#if ICAP_CLIENT
    icapHistory_ = NULL;
#endif
}

void
HttpRequest::reset()
{
    clean();
    init();
}

HttpRequest *
HttpRequest::clone() const
{
    HttpRequest *copy = new HttpRequest(masterXaction);
    copy->method = method;
    // TODO: move common cloning clone to Msg::copyTo() or copy ctor
    copy->header.append(&header);
    copy->hdrCacheInit();
    copy->hdr_sz = hdr_sz;
    copy->http_ver = http_ver;
    copy->pstate = pstate; // TODO: should we assert a specific state here?
    copy->body_pipe = body_pipe;

    copy->url = url;

    // range handled in hdrCacheInit()
    copy->ims = ims;
    copy->imslen = imslen;
    copy->hier = hier; // Is it safe to copy? Should we?

    copy->error = error;

    // XXX: what to do with copy->peer_login?

    copy->lastmod = lastmod;
    copy->etag = etag;
    copy->vary_headers = vary_headers;
    // XXX: what to do with copy->peer_domain?

    copy->tag = tag;
    copy->extacl_log = extacl_log;
    copy->extacl_message = extacl_message;

    const bool inheritWorked = copy->inheritProperties(this);
    assert(inheritWorked);

    return copy;
}

bool
HttpRequest::inheritProperties(const Http::Message *aMsg)
{
    const HttpRequest* aReq = dynamic_cast<const HttpRequest*>(aMsg);
    if (!aReq)
        return false;

    client_addr = aReq->client_addr;
#if FOLLOW_X_FORWARDED_FOR
    indirect_client_addr = aReq->indirect_client_addr;
#endif
    my_addr = aReq->my_addr;

    dnsWait = aReq->dnsWait;

#if USE_ADAPTATION
    adaptHistory_ = aReq->adaptHistory();
#endif
#if ICAP_CLIENT
    icapHistory_ = aReq->icapHistory();
#endif

    // This may be too conservative for the 204 No Content case
    // may eventually need cloneNullAdaptationImmune() for that.
    flags = aReq->flags.cloneAdaptationImmune();

    error = aReq->error;
#if USE_AUTH
    auth_user_request = aReq->auth_user_request;
    extacl_user = aReq->extacl_user;
    extacl_passwd = aReq->extacl_passwd;
#endif

    myportname = aReq->myportname;

    forcedBodyContinuation = aReq->forcedBodyContinuation;

    // main property is which connection the request was received on (if any)
    clientConnectionManager = aReq->clientConnectionManager;

    downloader = aReq->downloader;

    theNotes = aReq->theNotes;

    sources = aReq->sources;
    return true;
}

/**
 * Checks the first line of an HTTP request is valid
 * currently just checks the request method is present.
 *
 * NP: Other errors are left for detection later in the parse.
 */
bool
HttpRequest::sanityCheckStartLine(const char *buf, const size_t hdr_len, Http::StatusCode *scode)
{
    // content is long enough to possibly hold a reply
    // 2 being magic size of a 1-byte request method plus space delimiter
    if (hdr_len < 2) {
        // this is ony a real error if the headers apparently complete.
        if (hdr_len > 0) {
            debugs(58, 3, HERE << "Too large request header (" << hdr_len << " bytes)");
            *scode = Http::scInvalidHeader;
        }
        return false;
    }

    /* See if the request buffer starts with a non-whitespace HTTP request 'method'. */
    HttpRequestMethod m;
    m.HttpRequestMethodXXX(buf);
    if (m == Http::METHOD_NONE) {
        debugs(73, 3, "HttpRequest::sanityCheckStartLine: did not find HTTP request method");
        *scode = Http::scInvalidHeader;
        return false;
    }

    return true;
}

bool
HttpRequest::parseFirstLine(const char *start, const char *end)
{
    method.HttpRequestMethodXXX(start);

    if (method == Http::METHOD_NONE)
        return false;

    // XXX: performance regression, strcspn() over the method bytes a second time.
    // cheaper than allocate+copy+deallocate cycle to SBuf convert a piece of start.
    const char *t = start + strcspn(start, w_space);

    start = t + strspn(t, w_space); // skip w_space after method

    const char *ver = findTrailingHTTPVersion(start, end);

    if (ver) {
        end = ver - 1;

        while (xisspace(*end)) // find prev non-space
            --end;

        ++end;                 // back to space

        if (2 != sscanf(ver + 5, "%d.%d", &http_ver.major, &http_ver.minor)) {
            debugs(73, DBG_IMPORTANT, "parseRequestLine: Invalid HTTP identifier.");
            return false;
        }
    } else {
        http_ver.major = 0;
        http_ver.minor = 9;
    }

    if (end < start)   // missing URI
        return false;

    return url.parse(method, SBuf(start, size_t(end-start)));
}

/* swaps out request using httpRequestPack */
void
HttpRequest::swapOut(StoreEntry * e)
{
    assert(e);
    e->buffer();
    pack(e);
    e->flush();
}

/* packs request-line and headers, appends <crlf> terminator */
void
HttpRequest::pack(Packable * p) const
{
    assert(p);
    /* pack request-line */
    p->appendf(SQUIDSBUFPH " " SQUIDSBUFPH " HTTP/%d.%d\r\n",
               SQUIDSBUFPRINT(method.image()), SQUIDSBUFPRINT(url.path()),
               http_ver.major, http_ver.minor);
    /* headers */
    header.packInto(p);
    /* trailer */
    p->append("\r\n", 2);
}

/*
 * A wrapper for debugObj()
 */
void
httpRequestPack(void *obj, Packable *p)
{
    HttpRequest *request = static_cast<HttpRequest*>(obj);
    request->pack(p);
}

/* returns the length of request line + headers + crlf */
int
HttpRequest::prefixLen() const
{
    return method.image().length() + 1 +
           url.path().length() + 1 +
           4 + 1 + 3 + 2 +
           header.len + 2;
}

/* sync this routine when you update HttpRequest struct */
void
HttpRequest::hdrCacheInit()
{
    Http::Message::hdrCacheInit();

    assert(!range);
    range = header.getRange();
}

#if ICAP_CLIENT
Adaptation::Icap::History::Pointer
HttpRequest::icapHistory() const
{
    if (!icapHistory_) {
        if (Log::TheConfig.hasIcapToken || IcapLogfileStatus == LOG_ENABLE) {
            icapHistory_ = new Adaptation::Icap::History();
            debugs(93,4, HERE << "made " << icapHistory_ << " for " << this);
        }
    }

    return icapHistory_;
}
#endif

#if USE_ADAPTATION
Adaptation::History::Pointer
HttpRequest::adaptHistory(bool createIfNone) const
{
    if (!adaptHistory_ && createIfNone) {
        adaptHistory_ = new Adaptation::History();
        debugs(93,4, HERE << "made " << adaptHistory_ << " for " << this);
    }

    return adaptHistory_;
}

Adaptation::History::Pointer
HttpRequest::adaptLogHistory() const
{
    return HttpRequest::adaptHistory(Log::TheConfig.hasAdaptToken);
}

void
HttpRequest::adaptHistoryImport(const HttpRequest &them)
{
    if (!adaptHistory_) {
        adaptHistory_ = them.adaptHistory_; // may be nil
    } else {
        // check that histories did not diverge
        Must(!them.adaptHistory_ || them.adaptHistory_ == adaptHistory_);
    }
}

#endif

bool
HttpRequest::multipartRangeRequest() const
{
    return (range && range->specs.size() > 1);
}

bool
HttpRequest::bodyNibbled() const
{
    return body_pipe != NULL && body_pipe->consumedSize() > 0;
}

void
HttpRequest::prepForPeering(const CachePeer &peer)
{
    // XXX: Saving two pointers to memory controlled by an independent object.
    peer_login = peer.login;
    peer_domain = peer.domain;
    flags.auth_no_keytab = peer.options.auth_no_keytab;
    debugs(11, 4, this << " to " << peer.host << (!peer.options.originserver ? " proxy" : " origin"));
}

void
HttpRequest::prepForDirect()
{
    peer_login = nullptr;
    peer_domain = nullptr;
    flags.auth_no_keytab = false;
    debugs(11, 4, this);
}

void
HttpRequest::clearError()
{
    debugs(11, 7, "old: " << error);
    error.clear();
}

void
HttpRequest::packFirstLineInto(Packable * p, bool full_uri) const
{
    const SBuf tmp(full_uri ? effectiveRequestUri() : url.path());

    // form HTTP request-line
    p->appendf(SQUIDSBUFPH " " SQUIDSBUFPH " HTTP/%d.%d\r\n",
               SQUIDSBUFPRINT(method.image()),
               SQUIDSBUFPRINT(tmp),
               http_ver.major, http_ver.minor);
}

/*
 * Indicate whether or not we would expect an entity-body
 * along with this request
 */
bool
HttpRequest::expectingBody(const HttpRequestMethod &, int64_t &theSize) const
{
    bool expectBody = false;

    /*
     * Note: Checks for message validity is in clientIsContentLengthValid().
     * this just checks if a entity-body is expected based on HTTP message syntax
     */
    if (header.chunked()) {
        expectBody = true;
        theSize = -1;
    } else if (content_length >= 0) {
        expectBody = true;
        theSize = content_length;
    } else {
        expectBody = false;
        // theSize undefined
    }

    return expectBody;
}

/*
 * Create a Request from a URL and METHOD.
 *
 * If the METHOD is CONNECT, then a host:port pair is looked for instead of a URL.
 * If the request cannot be created cleanly, NULL is returned
 */
HttpRequest *
HttpRequest::FromUrl(const SBuf &url, const MasterXaction::Pointer &mx, const HttpRequestMethod& method)
{
    std::unique_ptr<HttpRequest> req(new HttpRequest(mx));
    if (req->url.parse(method, url)) {
        req->method = method;
        return req.release();
    }
    return nullptr;
}

HttpRequest *
HttpRequest::FromUrlXXX(const char * url, const MasterXaction::Pointer &mx, const HttpRequestMethod& method)
{
    return FromUrl(SBuf(url), mx, method);
}

/**
 * Are responses to this request possible cacheable ?
 * If false then no matter what the response must not be cached.
 */
bool
HttpRequest::maybeCacheable()
{
    // Intercepted request with Host: header which cannot be trusted.
    // Because it failed verification, or someone bypassed the security tests
    // we cannot cache the reponse for sharing between clients.
    // TODO: update cache to store for particular clients only (going to same Host: and destination IP)
    if (!flags.hostVerified && (flags.intercepted || flags.interceptTproxy))
        return false;

    switch (url.getScheme()) {
    case AnyP::PROTO_HTTP:
    case AnyP::PROTO_HTTPS:
        if (!method.respMaybeCacheable())
            return false;

        // RFC 7234 section 5.2.1.5:
        // "cache MUST NOT store any part of either this request or any response to it"
        //
        // NP: refresh_pattern ignore-no-store only applies to response messages
        //     this test is handling request message CC header.
        if (!flags.ignoreCc && cache_control && cache_control->hasNoStore())
            return false;
        break;

    case AnyP::PROTO_GOPHER:
        if (!gopherCachable(this))
            return false;
        break;

    case AnyP::PROTO_CACHE_OBJECT:
        return false;

    //case AnyP::PROTO_FTP:
    default:
        break;
    }

    return true;
}

bool
HttpRequest::conditional() const
{
    return flags.ims ||
           header.has(Http::HdrType::IF_MATCH) ||
           header.has(Http::HdrType::IF_NONE_MATCH);
}

void
HttpRequest::recordLookup(const Dns::LookupDetails &dns)
{
    if (dns.wait >= 0) { // known delay
        if (dnsWait >= 0) { // have recorded DNS wait before
            debugs(78, 7, this << " " << dnsWait << " += " << dns);
            dnsWait += dns.wait;
        } else {
            debugs(78, 7, this << " " << dns);
            dnsWait = dns.wait;
        }
    }
}

int64_t
HttpRequest::getRangeOffsetLimit()
{
    /* -2 is the starting value of rangeOffsetLimit.
     * If it is -2, that means we haven't checked it yet.
     *  Otherwise, return the current value */
    if (rangeOffsetLimit != -2)
        return rangeOffsetLimit;

    rangeOffsetLimit = 0; // default value for rangeOffsetLimit

    ACLFilledChecklist ch(NULL, this, NULL);
    ch.src_addr = client_addr;
    ch.my_addr =  my_addr;

    for (AclSizeLimit *l = Config.rangeOffsetLimit; l; l = l -> next) {
        /* if there is no ACL list or if the ACLs listed match use this limit value */
        if (!l->aclList || ch.fastCheck(l->aclList).allowed()) {
            rangeOffsetLimit = l->size; // may be -1
            debugs(58, 4, rangeOffsetLimit);
            break;
        }
    }

    return rangeOffsetLimit;
}

void
HttpRequest::ignoreRange(const char *reason)
{
    if (range) {
        debugs(73, 3, static_cast<void*>(range) << " for " << reason);
        delete range;
        range = NULL;
    }
    // Some callers also reset isRanged but it may not be safe for all callers:
    // isRanged is used to determine whether a weak ETag comparison is allowed,
    // and that check should not ignore the Range header if it was present.
    // TODO: Some callers also delete HDR_RANGE, HDR_REQUEST_RANGE. Should we?
}

bool
HttpRequest::canHandle1xx() const
{
    // old clients do not support 1xx unless they sent Expect: 100-continue
    // (we reject all other Http::HdrType::EXPECT values so just check for Http::HdrType::EXPECT)
    if (http_ver <= Http::ProtocolVersion(1,0) && !header.has(Http::HdrType::EXPECT))
        return false;

    // others must support 1xx control messages
    return true;
}

bool
HttpRequest::parseHeader(Http1::Parser &hp)
{
    Http::ContentLengthInterpreter clen;
    return Message::parseHeader(hp, clen);
}

bool
HttpRequest::parseHeader(const char *buffer, const size_t size)
{
    Http::ContentLengthInterpreter clen;
    return header.parse(buffer, size, clen);
}

ConnStateData *
HttpRequest::pinnedConnection()
{
    if (clientConnectionManager.valid() && clientConnectionManager->pinning.pinned)
        return clientConnectionManager.get();
    return NULL;
}

const SBuf
HttpRequest::storeId()
{
    if (store_id.size() != 0) {
        debugs(73, 3, "sent back store_id: " << store_id);
        return StringToSBuf(store_id);
    }
    debugs(73, 3, "sent back effectiveRequestUrl: " << effectiveRequestUri());
    return effectiveRequestUri();
}

const SBuf &
HttpRequest::effectiveRequestUri() const
{
    if (method.id() == Http::METHOD_CONNECT || url.getScheme() == AnyP::PROTO_AUTHORITY_FORM)
        return url.authority(true); // host:port
    return url.absolute();
}

NotePairs::Pointer
HttpRequest::notes()
{
    if (!theNotes)
        theNotes = new NotePairs;
    return theNotes;
}

void
UpdateRequestNotes(ConnStateData *csd, HttpRequest &request, NotePairs const &helperNotes)
{
    // Tag client connection if the helper responded with clt_conn_tag=tag.
    const char *cltTag = "clt_conn_tag";
    if (const char *connTag = helperNotes.findFirst(cltTag)) {
        if (csd) {
            csd->notes()->remove(cltTag);
            csd->notes()->add(cltTag, connTag);
        }
    }
    request.notes()->replaceOrAdd(&helperNotes);
}

void
HttpRequest::manager(const CbcPointer<ConnStateData> &aMgr, const AccessLogEntryPointer &al)
{
    clientConnectionManager = aMgr;

    if (!clientConnectionManager.valid())
        return;

    AnyP::PortCfgPointer port = clientConnectionManager->port;
    if (port) {
        myportname = port->name;
        flags.ignoreCc = port->ignore_cc;
    }

    if (auto clientConnection = clientConnectionManager->clientConnection) {
        client_addr = clientConnection->remote; // XXX: remove request->client_addr member.
#if FOLLOW_X_FORWARDED_FOR
        // indirect client gets stored here because it is an HTTP header result (from X-Forwarded-For:)
        // not details about the TCP connection itself
        indirect_client_addr = clientConnection->remote;
#endif /* FOLLOW_X_FORWARDED_FOR */
        my_addr = clientConnection->local;

        flags.intercepted = ((clientConnection->flags & COMM_INTERCEPTION) != 0);
        flags.interceptTproxy = ((clientConnection->flags & COMM_TRANSPARENT) != 0 ) ;
        const bool proxyProtocolPort = port ? port->flags.proxySurrogate : false;
        if (flags.interceptTproxy && !proxyProtocolPort) {
            if (Config.accessList.spoof_client_ip) {
                ACLFilledChecklist *checklist = new ACLFilledChecklist(Config.accessList.spoof_client_ip, this, clientConnection->rfc931);
                checklist->al = al;
                checklist->syncAle(this, nullptr);
                flags.spoofClientIp = checklist->fastCheck().allowed();
                delete checklist;
            } else
                flags.spoofClientIp = true;
        } else
            flags.spoofClientIp = false;
    }
}

char *
HttpRequest::canonicalCleanUrl() const
{
    return urlCanonicalCleanWithoutRequest(effectiveRequestUri(), method, url.getScheme());
}

/// a helper for validating FindListeningPortAddress()-found address candidates
static const Ip::Address *
FindListeningPortAddressInAddress(const Ip::Address *ip)
{
    // FindListeningPortAddress() callers do not want INADDR_ANY addresses
    return (ip && !ip->isAnyAddr()) ? ip : nullptr;
}

/// a helper for handling PortCfg cases of FindListeningPortAddress()
static const Ip::Address *
FindListeningPortAddressInPort(const AnyP::PortCfgPointer &port)
{
    return port ? FindListeningPortAddressInAddress(&port->s) : nullptr;
}

/// a helper for handling Connection cases of FindListeningPortAddress()
static const Ip::Address *
FindListeningPortAddressInConn(const Comm::ConnectionPointer &conn)
{
    return conn ? FindListeningPortAddressInAddress(&conn->local) : nullptr;
}

const Ip::Address *
FindListeningPortAddress(const HttpRequest *callerRequest, const AccessLogEntry *ale)
{
    // Check all sources of usable listening port information, giving
    // HttpRequest and masterXaction a preference over ALE.

    const HttpRequest *request = callerRequest;
    if (!request && ale)
        request = ale->request;
    if (!request)
        return nullptr; // not enough information

    const Ip::Address *ip = FindListeningPortAddressInPort(request->masterXaction->squidPort);
    if (!ip && ale)
        ip = FindListeningPortAddressInPort(ale->cache.port);

    // XXX: also handle PROXY protocol here when we have a flag to identify such request
    if (ip || request->flags.interceptTproxy || request->flags.intercepted)
        return ip;

    /* handle non-intercepted cases that were not handled above */
    ip = FindListeningPortAddressInConn(request->masterXaction->tcpClient);
    if (!ip && ale)
        ip = FindListeningPortAddressInConn(ale->tcpClient);
    return ip; // may still be nil
}

