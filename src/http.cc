/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 11    Hypertext Transfer Protocol (HTTP) */

/*
 * Anonymizing patch by lutz@as-node.jena.thur.de
 * have a look into http-anon.c to get more informations.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "base/AsyncJobCalls.h"
#include "base/TextException.h"
#include "base64.h"
#include "CachePeer.h"
#include "client_side.h"
#include "comm/Connection.h"
#include "comm/Read.h"
#include "comm/Write.h"
#include "CommRead.h"
#include "err_detail_type.h"
#include "errorpage.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "http.h"
#include "http/one/ResponseParser.h"
#include "http/one/TeChunkedParser.h"
#include "http/Stream.h"
#include "HttpControlMsg.h"
#include "HttpHdrCc.h"
#include "HttpHdrContRange.h"
#include "HttpHdrSc.h"
#include "HttpHdrScTarget.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "log/access_log.h"
#include "MemBuf.h"
#include "MemObject.h"
#include "neighbors.h"
#include "pconn.h"
#include "peer_proxy_negotiate_auth.h"
#include "profiler/Profiler.h"
#include "refresh.h"
#include "RefreshPattern.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "Store.h"
#include "StrList.h"
#include "tools.h"
#include "util.h"

#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if USE_DELAY_POOLS
#include "DelayPools.h"
#endif

#define SQUID_ENTER_THROWING_CODE() try {
#define SQUID_EXIT_THROWING_CODE(status) \
    status = true; \
    } \
    catch (const std::exception &e) { \
    debugs (11, 1, "Exception error:" << e.what()); \
    status = false; \
    }

CBDATA_CLASS_INIT(HttpStateData);

static const char *const crlf = "\r\n";

static void httpMaybeRemovePublic(StoreEntry *, Http::StatusCode);
static void copyOneHeaderFromClientsideRequestToUpstreamRequest(const HttpHeaderEntry *e, const String strConnection, const HttpRequest * request,
        HttpHeader * hdr_out, const int we_do_ranges, const Http::StateFlags &);

HttpStateData::HttpStateData(FwdState *theFwdState) :
    AsyncJob("HttpStateData"),
    Client(theFwdState),
    lastChunk(0),
    httpChunkDecoder(NULL),
    payloadSeen(0),
    payloadTruncated(0),
    sawDateGoBack(false)
{
    debugs(11,5,HERE << "HttpStateData " << this << " created");
    ignoreCacheControl = false;
    surrogateNoStore = false;
    serverConnection = fwd->serverConnection();

    if (fwd->serverConnection() != NULL)
        _peer = cbdataReference(fwd->serverConnection()->getPeer());         /* might be NULL */

    flags.peering =  _peer;
    flags.tunneling = (_peer && request->flags.sslBumped);
    flags.toOrigin = (!_peer || _peer->options.originserver || request->flags.sslBumped);

    if (_peer) {
        /*
         * This NEIGHBOR_PROXY_ONLY check probably shouldn't be here.
         * We might end up getting the object from somewhere else if,
         * for example, the request to this neighbor fails.
         */
        if (!flags.tunneling && _peer->options.proxy_only)
            entry->releaseRequest(true);

#if USE_DELAY_POOLS
        entry->setNoDelay(_peer->options.no_delay);
#endif
    }

    /*
     * register the handler to free HTTP state data when the FD closes
     */
    typedef CommCbMemFunT<HttpStateData, CommCloseCbParams> Dialer;
    closeHandler = JobCallback(9, 5, Dialer, this, HttpStateData::httpStateConnClosed);
    comm_add_close_handler(serverConnection->fd, closeHandler);
}

HttpStateData::~HttpStateData()
{
    /*
     * don't forget that ~Client() gets called automatically
     */

    if (httpChunkDecoder)
        delete httpChunkDecoder;

    cbdataReferenceDone(_peer);

    debugs(11,5, HERE << "HttpStateData " << this << " destroyed; " << serverConnection);
}

const Comm::ConnectionPointer &
HttpStateData::dataConnection() const
{
    return serverConnection;
}

void
HttpStateData::httpStateConnClosed(const CommCloseCbParams &params)
{
    debugs(11, 5, "httpStateFree: FD " << params.fd << ", httpState=" << params.data);
    doneWithFwd = "httpStateConnClosed()"; // assume FwdState is monitoring too
    mustStop("HttpStateData::httpStateConnClosed");
}

void
HttpStateData::httpTimeout(const CommTimeoutCbParams &)
{
    debugs(11, 4, serverConnection << ": '" << entry->url() << "'");

    if (entry->store_status == STORE_PENDING) {
        fwd->fail(new ErrorState(ERR_READ_TIMEOUT, Http::scGatewayTimeout, fwd->request, fwd->al));
    }

    closeServer();
    mustStop("HttpStateData::httpTimeout");
}

static StoreEntry *
findPreviouslyCachedEntry(StoreEntry *newEntry) {
    assert(newEntry->mem_obj);
    return newEntry->mem_obj->request ?
           storeGetPublicByRequest(newEntry->mem_obj->request.getRaw()) :
           storeGetPublic(newEntry->mem_obj->storeId(), newEntry->mem_obj->method);
}

/// Remove an existing public store entry if the incoming response (to be
/// stored in a currently private entry) is going to invalidate it.
static void
httpMaybeRemovePublic(StoreEntry * e, Http::StatusCode status)
{
    int remove = 0;
    int forbidden = 0;

    // If the incoming response already goes into a public entry, then there is
    // nothing to remove. This protects ready-for-collapsing entries as well.
    if (!EBIT_TEST(e->flags, KEY_PRIVATE))
        return;

    // If the new/incoming response cannot be stored, then it does not
    // compete with the old stored response for the public key, and the
    // old stored response should be left as is.
    if (e->mem_obj->request && !e->mem_obj->request->flags.cachable)
        return;

    switch (status) {

    case Http::scOkay:

    case Http::scNonAuthoritativeInformation:

    case Http::scMultipleChoices:

    case Http::scMovedPermanently:

    case Http::scFound:

    case Http::scSeeOther:

    case Http::scGone:

    case Http::scNotFound:
        remove = 1;

        break;

    case Http::scForbidden:

    case Http::scMethodNotAllowed:
        forbidden = 1;

        break;

#if WORK_IN_PROGRESS

    case Http::scUnauthorized:
        forbidden = 1;

        break;

#endif

    default:
#if QUESTIONABLE
        /*
         * Any 2xx response should eject previously cached entities...
         */

        if (status >= 200 && status < 300)
            remove = 1;

#endif

        break;
    }

    if (!remove && !forbidden)
        return;

    StoreEntry *pe = findPreviouslyCachedEntry(e);

    if (pe != NULL) {
        assert(e != pe);
#if USE_HTCP
        neighborsHtcpClear(e, nullptr, e->mem_obj->request.getRaw(), e->mem_obj->method, HTCP_CLR_INVALIDATION);
#endif
        pe->release(true);
    }

    /** \par
     * Also remove any cached HEAD response in case the object has
     * changed.
     */
    if (e->mem_obj->request)
        pe = storeGetPublicByRequestMethod(e->mem_obj->request.getRaw(), Http::METHOD_HEAD);
    else
        pe = storeGetPublic(e->mem_obj->storeId(), Http::METHOD_HEAD);

    if (pe != NULL) {
        assert(e != pe);
#if USE_HTCP
        neighborsHtcpClear(e, nullptr, e->mem_obj->request.getRaw(), HttpRequestMethod(Http::METHOD_HEAD), HTCP_CLR_INVALIDATION);
#endif
        pe->release(true);
    }
}

void
HttpStateData::processSurrogateControl(HttpReply *reply)
{
    if (request->flags.accelerated && reply->surrogate_control) {
        HttpHdrScTarget *sctusable = reply->surrogate_control->getMergedTarget(Config.Accel.surrogate_id);

        if (sctusable) {
            if (sctusable->hasNoStore() ||
                    (Config.onoff.surrogate_is_remote
                     && sctusable->noStoreRemote())) {
                surrogateNoStore = true;
                // Be conservative for now and make it non-shareable because
                // there is no enough information here to make the decision.
                entry->makePrivate(false);
            }

            /* The HttpHeader logic cannot tell if the header it's parsing is a reply to an
             * accelerated request or not...
             * Still, this is an abstraction breach. - RC
             */
            if (sctusable->hasMaxAge()) {
                if (sctusable->maxAge() < sctusable->maxStale())
                    reply->expires = reply->date + sctusable->maxAge();
                else
                    reply->expires = reply->date + sctusable->maxStale();

                /* And update the timestamps */
                entry->timestampsSet();
            }

            /* We ignore cache-control directives as per the Surrogate specification */
            ignoreCacheControl = true;

            delete sctusable;
        }
    }
}

HttpStateData::ReuseDecision::Answers
HttpStateData::reusableReply(HttpStateData::ReuseDecision &decision)
{
    HttpReply const *rep = finalReply();
    HttpHeader const *hdr = &rep->header;
    const char *v;
#if USE_HTTP_VIOLATIONS

    const RefreshPattern *R = NULL;

    /* This strange looking define first looks up the refresh pattern
     * and then checks if the specified flag is set. The main purpose
     * of this is to simplify the refresh pattern lookup and USE_HTTP_VIOLATIONS
     * condition
     */
#define REFRESH_OVERRIDE(flag) \
    ((R = (R ? R : refreshLimits(entry->mem_obj->storeId()))) , \
    (R && R->flags.flag))
#else
#define REFRESH_OVERRIDE(flag) 0
#endif

    if (EBIT_TEST(entry->flags, RELEASE_REQUEST))
        return decision.make(ReuseDecision::doNotCacheButShare, "the entry has been released");

    // RFC 7234 section 4: a cache MUST use the most recent response
    // (as determined by the Date header field)
    // TODO: whether such responses could be shareable?
    if (sawDateGoBack)
        return decision.make(ReuseDecision::reuseNot, "the response has an older date header");

    // Check for Surrogate/1.0 protocol conditions
    // NP: reverse-proxy traffic our parent server has instructed us never to cache
    if (surrogateNoStore)
        return decision.make(ReuseDecision::reuseNot, "Surrogate-Control:no-store");

    // RFC 2616: HTTP/1.1 Cache-Control conditions
    if (!ignoreCacheControl) {
        // XXX: check to see if the request headers alone were enough to prevent caching earlier
        // (ie no-store request header) no need to check those all again here if so.
        // for now we are not reliably doing that so we waste CPU re-checking request CC

        // RFC 2616 section 14.9.2 - MUST NOT cache any response with request CC:no-store
        if (request && request->cache_control && request->cache_control->hasNoStore() &&
                !REFRESH_OVERRIDE(ignore_no_store))
            return decision.make(ReuseDecision::reuseNot,
                                 "client request Cache-Control:no-store");

        // NP: request CC:no-cache only means cache READ is forbidden. STORE is permitted.
        if (rep->cache_control && rep->cache_control->hasNoCacheWithParameters()) {
            /* TODO: we are allowed to cache when no-cache= has parameters.
             * Provided we strip away any of the listed headers unless they are revalidated
             * successfully (ie, must revalidate AND these headers are prohibited on stale replies).
             * That is a bit tricky for squid right now so we avoid caching entirely.
             */
            return decision.make(ReuseDecision::reuseNot,
                                 "server reply Cache-Control:no-cache has parameters");
        }

        // NP: request CC:private is undefined. We ignore.
        // NP: other request CC flags are limiters on HIT/MISS. We don't care about here.

        // RFC 2616 section 14.9.2 - MUST NOT cache any response with CC:no-store
        if (rep->cache_control && rep->cache_control->hasNoStore() &&
                !REFRESH_OVERRIDE(ignore_no_store))
            return decision.make(ReuseDecision::reuseNot,
                                 "server reply Cache-Control:no-store");

        // RFC 2616 section 14.9.1 - MUST NOT cache any response with CC:private in a shared cache like Squid.
        // CC:private overrides CC:public when both are present in a response.
        // TODO: add a shared/private cache configuration possibility.
        if (rep->cache_control &&
                rep->cache_control->hasPrivate() &&
                !REFRESH_OVERRIDE(ignore_private)) {
            /* TODO: we are allowed to cache when private= has parameters.
             * Provided we strip away any of the listed headers unless they are revalidated
             * successfully (ie, must revalidate AND these headers are prohibited on stale replies).
             * That is a bit tricky for squid right now so we avoid caching entirely.
             */
            return decision.make(ReuseDecision::reuseNot,
                                 "server reply Cache-Control:private");
        }
    }

    // RFC 2068, sec 14.9.4 - MUST NOT cache any response with Authentication UNLESS certain CC controls are present
    // allow HTTP violations to IGNORE those controls (ie re-block caching Auth)
    if (request && (request->flags.auth || request->flags.authSent)) {
        if (!rep->cache_control)
            return decision.make(ReuseDecision::reuseNot,
                                 "authenticated and server reply missing Cache-Control");

        if (ignoreCacheControl)
            return decision.make(ReuseDecision::reuseNot,
                                 "authenticated and ignoring Cache-Control");

        bool mayStore = false;
        // HTTPbis pt6 section 3.2: a response CC:public is present
        if (rep->cache_control->hasPublic()) {
            debugs(22, 3, HERE << "Authenticated but server reply Cache-Control:public");
            mayStore = true;

            // HTTPbis pt6 section 3.2: a response CC:must-revalidate is present
        } else if (rep->cache_control->hasMustRevalidate()) {
            debugs(22, 3, HERE << "Authenticated but server reply Cache-Control:must-revalidate");
            mayStore = true;

#if USE_HTTP_VIOLATIONS
            // NP: given the must-revalidate exception we should also be able to exempt no-cache.
            // HTTPbis WG verdict on this is that it is omitted from the spec due to being 'unexpected' by
            // some. The caching+revalidate is not exactly unsafe though with Squids interpretation of no-cache
            // (without parameters) as equivalent to must-revalidate in the reply.
        } else if (rep->cache_control->hasNoCacheWithoutParameters()) {
            debugs(22, 3, HERE << "Authenticated but server reply Cache-Control:no-cache (equivalent to must-revalidate)");
            mayStore = true;
#endif

            // HTTPbis pt6 section 3.2: a response CC:s-maxage is present
        } else if (rep->cache_control->hasSMaxAge()) {
            debugs(22, 3, HERE << "Authenticated but server reply Cache-Control:s-maxage");
            mayStore = true;
        }

        if (!mayStore)
            return decision.make(ReuseDecision::reuseNot, "authenticated transaction");

        // NP: response CC:no-cache is equivalent to CC:must-revalidate,max-age=0. We MAY cache, and do so.
        // NP: other request CC flags are limiters on HIT/MISS/REFRESH. We don't care about here.
    }

    /* HACK: The "multipart/x-mixed-replace" content type is used for
     * continuous push replies.  These are generally dynamic and
     * probably should not be cachable
     */
    if ((v = hdr->getStr(Http::HdrType::CONTENT_TYPE)))
        if (!strncasecmp(v, "multipart/x-mixed-replace", 25))
            return decision.make(ReuseDecision::reuseNot, "Content-Type:multipart/x-mixed-replace");

    // TODO: if possible, provide more specific message for each status code
    static const char *shareableError = "shareable error status code";
    static const char *nonShareableError = "non-shareable error status code";
    ReuseDecision::Answers statusAnswer = ReuseDecision::reuseNot;
    const char *statusReason = nonShareableError;

    switch (rep->sline.status()) {

    /* There are several situations when a non-cacheable response may be
     * still shareable (e.g., among collapsed clients). We assume that these
     * are 3xx and 5xx responses, indicating server problems and some of
     * 4xx responses, common for all clients with a given cache key (e.g.,
     * 404 Not Found or 414 URI Too Long). On the other hand, we should not
     * share non-cacheable client-specific errors, such as 400 Bad Request
     * or 406 Not Acceptable.
     */

    /* Responses that are cacheable */

    case Http::scOkay:

    case Http::scNonAuthoritativeInformation:

    case Http::scMultipleChoices:

    case Http::scMovedPermanently:
    case Http::scPermanentRedirect:

    case Http::scGone:
        /*
         * Don't cache objects that need to be refreshed on next request,
         * unless we know how to refresh it.
         */

        if (refreshIsCachable(entry) || REFRESH_OVERRIDE(store_stale))
            decision.make(ReuseDecision::cachePositively, "refresh check returned cacheable");
        else
            decision.make(ReuseDecision::doNotCacheButShare, "refresh check returned non-cacheable");
        break;

    /* Responses that only are cacheable if the server says so */

    case Http::scFound:
    case Http::scTemporaryRedirect:
        if (rep->date <= 0)
            decision.make(ReuseDecision::doNotCacheButShare, "Date is missing/invalid");
        else if (rep->expires > rep->date)
            decision.make(ReuseDecision::cachePositively, "Expires > Date");
        else
            decision.make(ReuseDecision::doNotCacheButShare, "Expires <= Date");
        break;

    /* These responses can be negatively cached. Most can also be shared. */
    case Http::scNoContent:
    case Http::scUseProxy:
    case Http::scForbidden:
    case Http::scNotFound:
    case Http::scMethodNotAllowed:
    case Http::scUriTooLong:
    case Http::scInternalServerError:
    case Http::scNotImplemented:
    case Http::scBadGateway:
    case Http::scServiceUnavailable:
    case Http::scGatewayTimeout:
    case Http::scMisdirectedRequest:
        statusAnswer = ReuseDecision::doNotCacheButShare;
        statusReason = shareableError;
    // fall through to the actual decision making below

    case Http::scBadRequest: // no sharing; perhaps the server did not like something specific to this request
#if USE_HTTP_VIOLATIONS
        if (Config.negativeTtl > 0)
            decision.make(ReuseDecision::cacheNegatively, "Config.negativeTtl > 0");
        else
#endif
            decision.make(statusAnswer, statusReason);
        break;

    /* these responses can never be cached, some
       of them can be shared though */
    case Http::scSeeOther:
    case Http::scNotModified:
    case Http::scUnauthorized:
    case Http::scProxyAuthenticationRequired:
    case Http::scPaymentRequired:
    case Http::scInsufficientStorage:
        // TODO: use more specific reason for non-error status codes
        decision.make(ReuseDecision::doNotCacheButShare, shareableError);
        break;

    case Http::scPartialContent: /* Not yet supported. TODO: make shareable for suitable ranges */
    case Http::scNotAcceptable:
    case Http::scRequestTimeout: // TODO: is this shareable?
    case Http::scConflict: // TODO: is this shareable?
    case Http::scLengthRequired:
    case Http::scPreconditionFailed:
    case Http::scPayloadTooLarge:
    case Http::scUnsupportedMediaType:
    case Http::scUnprocessableEntity:
    case Http::scLocked: // TODO: is this shareable?
    case Http::scFailedDependency:
    case Http::scRequestedRangeNotSatisfied:
    case Http::scExpectationFailed:
    case Http::scInvalidHeader: /* Squid header parsing error */
    case Http::scHeaderTooLarge:
        decision.make(ReuseDecision::reuseNot, nonShareableError);
        break;

    default:
        /* RFC 2616 section 6.1.1: an unrecognized response MUST NOT be cached. */
        decision.make(ReuseDecision::reuseNot, "unknown status code");
        break;
    }

    return decision.answer;
}

/// assemble a variant key (vary-mark) from the given Vary header and HTTP request
static void
assembleVaryKey(String &vary, SBuf &vstr, const HttpRequest &request)
{
    static const SBuf asterisk("*");
    const char *pos = nullptr;
    const char *item = nullptr;
    int ilen = 0;

    while (strListGetItem(&vary, ',', &item, &ilen, &pos)) {
        SBuf name(item, ilen);
        if (name == asterisk) {
            vstr = asterisk;
            break;
        }
        name.toLower();
        if (!vstr.isEmpty())
            vstr.append(", ", 2);
        vstr.append(name);
        String hdr(request.header.getByName(name));
        const char *value = hdr.termedBuf();
        if (value) {
            value = rfc1738_escape_part(value);
            vstr.append("=\"", 2);
            vstr.append(value);
            vstr.append("\"", 1);
        }

        hdr.clean();
    }
}

/*
 * For Vary, store the relevant request headers as
 * virtual headers in the reply
 * Returns an empty SBuf if the variance cannot be stored
 */
SBuf
httpMakeVaryMark(HttpRequest * request, HttpReply const * reply)
{
    SBuf vstr;
    String vary;

    vary = reply->header.getList(Http::HdrType::VARY);
    assembleVaryKey(vary, vstr, *request);

#if X_ACCELERATOR_VARY
    vary.clean();
    vary = reply->header.getList(Http::HdrType::HDR_X_ACCELERATOR_VARY);
    assembleVaryKey(vary, vstr, *request);
#endif

    debugs(11, 3, vstr);
    return vstr;
}

void
HttpStateData::keepaliveAccounting(HttpReply *reply)
{
    if (flags.keepalive)
        if (flags.peering && !flags.tunneling)
            ++ _peer->stats.n_keepalives_sent;

    if (reply->keep_alive) {
        if (flags.peering && !flags.tunneling)
            ++ _peer->stats.n_keepalives_recv;

        if (Config.onoff.detect_broken_server_pconns
                && reply->bodySize(request->method) == -1 && !flags.chunked) {
            debugs(11, DBG_IMPORTANT, "keepaliveAccounting: Impossible keep-alive header from '" << entry->url() << "'" );
            // debugs(11, 2, "GOT HTTP REPLY HDR:\n---------\n" << readBuf->content() << "\n----------" );
            flags.keepalive_broken = true;
        }
    }
}

void
HttpStateData::checkDateSkew(HttpReply *reply)
{
    if (reply->date > -1 && flags.toOrigin) {
        int skew = abs((int)(reply->date - squid_curtime));

        if (skew > 86400)
            debugs(11, 3, "" << request->url.host() << "'s clock is skewed by " << skew << " seconds!");
    }
}

/**
 * This creates the error page itself.. its likely
 * that the forward ported reply header max size patch
 * generates non http conformant error pages - in which
 * case the errors where should be 'BAD_GATEWAY' etc
 */
void
HttpStateData::processReplyHeader()
{
    /** Creates a blank header. If this routine is made incremental, this will not do */

    /* NP: all exit points to this function MUST call ctx_exit(ctx) */
    Ctx ctx = ctx_enter(entry->mem_obj->urlXXX());

    debugs(11, 3, "processReplyHeader: key '" << entry->getMD5Text() << "'");

    assert(!flags.headers_parsed);

    if (!inBuf.length()) {
        ctx_exit(ctx);
        return;
    }

    /* Attempt to parse the first line; this will define where the protocol, status, reason-phrase and header begin */
    {
        if (hp == NULL)
            hp = new Http1::ResponseParser;

        bool parsedOk = hp->parse(inBuf);

        // sync the buffers after parsing.
        inBuf = hp->remaining();

        if (hp->needsMoreData()) {
            if (eof) { // no more data coming
                /* Bug 2879: Replies may terminate with \r\n then EOF instead of \r\n\r\n.
                 * We also may receive truncated responses.
                 * Ensure here that we have at minimum two \r\n when EOF is seen.
                 */
                inBuf.append("\r\n\r\n", 4);
                // retry the parse
                parsedOk = hp->parse(inBuf);
                // sync the buffers after parsing.
                inBuf = hp->remaining();
            } else {
                debugs(33, 5, "Incomplete response, waiting for end of response headers");
                ctx_exit(ctx);
                return;
            }
        }

        if (!parsedOk) {
            // unrecoverable parsing error
            // TODO: Use Raw! XXX: inBuf no longer has the [beginning of the] malformed header.
            debugs(11, 3, "Non-HTTP-compliant header:\n---------\n" << inBuf << "\n----------");
            flags.headers_parsed = true;
            HttpReply *newrep = new HttpReply;
            newrep->sline.set(Http::ProtocolVersion(), hp->parseStatusCode);
            setVirginReply(newrep);
            ctx_exit(ctx);
            return;
        }
    }

    /* We know the whole response is in parser now */
    debugs(11, 2, "HTTP Server " << serverConnection);
    debugs(11, 2, "HTTP Server RESPONSE:\n---------\n" <<
           hp->messageProtocol() << " " << hp->messageStatus() << " " << hp->reasonPhrase() << "\n" <<
           hp->mimeHeader() <<
           "----------");

    // reset payload tracking to begin after message headers
    payloadSeen = inBuf.length();

    HttpReply *newrep = new HttpReply;
    // XXX: RFC 7230 indicates we MAY ignore the reason phrase,
    //      and use an empty string on unknown status.
    //      We do that now to avoid performance regression from using SBuf::c_str()
    newrep->sline.set(Http::ProtocolVersion(1,1), hp->messageStatus() /* , hp->reasonPhrase() */);
    newrep->sline.protocol = newrep->sline.version.protocol = hp->messageProtocol().protocol;
    newrep->sline.version.major = hp->messageProtocol().major;
    newrep->sline.version.minor = hp->messageProtocol().minor;

    // parse headers
    if (!newrep->parseHeader(*hp)) {
        // XXX: when Http::ProtocolVersion is a function, remove this hack. just set with messageProtocol()
        newrep->sline.set(Http::ProtocolVersion(), Http::scInvalidHeader);
        newrep->sline.version.protocol = hp->messageProtocol().protocol;
        newrep->sline.version.major = hp->messageProtocol().major;
        newrep->sline.version.minor = hp->messageProtocol().minor;
        debugs(11, 2, "error parsing response headers mime block");
    }

    // done with Parser, now process using the HttpReply
    hp = NULL;

    newrep->sources |= request->url.getScheme() == AnyP::PROTO_HTTPS ? Http::Message::srcHttps : Http::Message::srcHttp;

    newrep->removeStaleWarnings();

    if (newrep->sline.protocol == AnyP::PROTO_HTTP && Http::Is1xx(newrep->sline.status())) {
        handle1xx(newrep);
        ctx_exit(ctx);
        return;
    }

    flags.chunked = false;
    if (newrep->sline.protocol == AnyP::PROTO_HTTP && newrep->header.chunked()) {
        flags.chunked = true;
        httpChunkDecoder = new Http1::TeChunkedParser;
    }

    if (!peerSupportsConnectionPinning())
        request->flags.connectionAuthDisabled = true;

    HttpReply *vrep = setVirginReply(newrep);
    flags.headers_parsed = true;

    keepaliveAccounting(vrep);

    checkDateSkew(vrep);

    processSurrogateControl (vrep);

    request->hier.peer_reply_status = newrep->sline.status();

    ctx_exit(ctx);
}

/// ignore or start forwarding the 1xx response (a.k.a., control message)
void
HttpStateData::handle1xx(HttpReply *reply)
{
    if (fwd->al)
        fwd->al->reply = reply;

    HttpReply::Pointer msg(reply); // will destroy reply if unused

    // one 1xx at a time: we must not be called while waiting for previous 1xx
    Must(!flags.handling1xx);
    flags.handling1xx = true;

    if (!request->canHandle1xx() || request->forcedBodyContinuation) {
        debugs(11, 2, "ignoring 1xx because it is " << (request->forcedBodyContinuation ? "already sent" : "not supported by client"));
        proceedAfter1xx();
        return;
    }

#if USE_HTTP_VIOLATIONS
    // check whether the 1xx response forwarding is allowed by squid.conf
    if (Config.accessList.reply) {
        ACLFilledChecklist ch(Config.accessList.reply, originalRequest().getRaw());
        ch.al = fwd->al;
        ch.reply = reply;
        ch.syncAle(originalRequest().getRaw(), nullptr);
        HTTPMSGLOCK(ch.reply);
        if (!ch.fastCheck().allowed()) { // TODO: support slow lookups?
            debugs(11, 3, HERE << "ignoring denied 1xx");
            proceedAfter1xx();
            return;
        }
    }
#endif // USE_HTTP_VIOLATIONS

    debugs(11, 2, HERE << "forwarding 1xx to client");

    // the Sink will use this to call us back after writing 1xx to the client
    typedef NullaryMemFunT<HttpStateData> CbDialer;
    const AsyncCall::Pointer cb = JobCallback(11, 3, CbDialer, this,
                                  HttpStateData::proceedAfter1xx);
    CallJobHere1(11, 4, request->clientConnectionManager, ConnStateData,
                 ConnStateData::sendControlMsg, HttpControlMsg(msg, cb));
    // If the call is not fired, then the Sink is gone, and HttpStateData
    // will terminate due to an aborted store entry or another similar error.
    // If we get stuck, it is not handle1xx fault if we could get stuck
    // for similar reasons without a 1xx response.
}

/// restores state and resumes processing after 1xx is ignored or forwarded
void
HttpStateData::proceedAfter1xx()
{
    Must(flags.handling1xx);
    debugs(11, 2, "continuing with " << payloadSeen << " bytes in buffer after 1xx");
    CallJobHere(11, 3, this, HttpStateData, HttpStateData::processReply);
}

/**
 * returns true if the peer can support connection pinning
*/
bool
HttpStateData::peerSupportsConnectionPinning() const
{
    if (!_peer)
        return true;

    // we are talking "through" rather than "to" our _peer
    if (flags.tunneling)
        return true;

    /*If this peer does not support connection pinning (authenticated
      connections) return false
     */
    if (!_peer->connection_auth)
        return false;

    const auto &rep = entry->mem().freshestReply();

    /*The peer supports connection pinning and the http reply status
      is not unauthorized, so the related connection can be pinned
     */
    if (rep.sline.status() != Http::scUnauthorized)
        return true;

    /*The server respond with Http::scUnauthorized and the peer configured
      with "connection-auth=on" we know that the peer supports pinned
      connections
    */
    if (_peer->connection_auth == 1)
        return true;

    /*At this point peer has configured with "connection-auth=auto"
      parameter so we need some extra checks to decide if we are going
      to allow pinned connections or not
    */

    /*if the peer configured with originserver just allow connection
        pinning (squid 2.6 behaviour)
     */
    if (_peer->options.originserver)
        return true;

    /*if the connections it is already pinned it is OK*/
    if (request->flags.pinned)
        return true;

    /*Allow pinned connections only if the Proxy-support header exists in
      reply and has in its list the "Session-Based-Authentication"
      which means that the peer supports connection pinning.
     */
    if (rep.header.hasListMember(Http::HdrType::PROXY_SUPPORT, "Session-Based-Authentication", ','))
        return true;

    return false;
}

// Called when we parsed (and possibly adapted) the headers but
// had not starting storing (a.k.a., sending) the body yet.
void
HttpStateData::haveParsedReplyHeaders()
{
    Client::haveParsedReplyHeaders();

    Ctx ctx = ctx_enter(entry->mem_obj->urlXXX());
    HttpReply *rep = finalReply();
    const Http::StatusCode statusCode = rep->sline.status();

    entry->timestampsSet();

    /* Check if object is cacheable or not based on reply code */
    debugs(11, 3, "HTTP CODE: " << statusCode);

    if (StoreEntry *oldEntry = findPreviouslyCachedEntry(entry)) {
        oldEntry->lock("HttpStateData::haveParsedReplyHeaders");
        sawDateGoBack = rep->olderThan(oldEntry->hasFreshestReply());
        oldEntry->unlock("HttpStateData::haveParsedReplyHeaders");
    }

    if (neighbors_do_private_keys && !sawDateGoBack)
        httpMaybeRemovePublic(entry, rep->sline.status());

    bool varyFailure = false;
    if (rep->header.has(Http::HdrType::VARY)
#if X_ACCELERATOR_VARY
            || rep->header.has(Http::HdrType::HDR_X_ACCELERATOR_VARY)
#endif
       ) {
        const SBuf vary(httpMakeVaryMark(request.getRaw(), rep));

        if (vary.isEmpty()) {
            // TODO: check whether such responses are shareable.
            // Do not share for now.
            entry->makePrivate(false);
            if (fwd->reforwardableStatus(rep->sline.status()))
                EBIT_SET(entry->flags, ENTRY_FWD_HDR_WAIT);
            varyFailure = true;
        } else {
            entry->mem_obj->vary_headers = vary;

            // RFC 7231 section 7.1.4
            // Vary:* can be cached, but has mandatory revalidation
            static const SBuf asterisk("*");
            if (vary == asterisk)
                EBIT_SET(entry->flags, ENTRY_REVALIDATE_ALWAYS);
        }
    }

    if (!varyFailure) {
        /*
         * If its not a reply that we will re-forward, then
         * allow the client to get it.
         */
        if (fwd->reforwardableStatus(rep->sline.status()))
            EBIT_SET(entry->flags, ENTRY_FWD_HDR_WAIT);

        ReuseDecision decision(entry, statusCode);

        switch (reusableReply(decision)) {

        case ReuseDecision::reuseNot:
            entry->makePrivate(false);
            break;

        case ReuseDecision::cachePositively:
            if (!entry->makePublic()) {
                decision.make(ReuseDecision::doNotCacheButShare, "public key creation error");
                entry->makePrivate(true);
            }
            break;

        case ReuseDecision::cacheNegatively:
            if (!entry->cacheNegatively()) {
                decision.make(ReuseDecision::doNotCacheButShare, "public key creation error");
                entry->makePrivate(true);
            }
            break;

        case ReuseDecision::doNotCacheButShare:
            entry->makePrivate(true);
            break;

        default:
            assert(0);
            break;
        }
        debugs(11, 3, "decided: " << decision);
    }

    if (!ignoreCacheControl) {
        if (rep->cache_control) {
            // We are required to revalidate on many conditions.
            // For security reasons we do so even if storage was caused by refresh_pattern ignore-* option

            // CC:must-revalidate or CC:proxy-revalidate
            const bool ccMustRevalidate = (rep->cache_control->hasProxyRevalidate() || rep->cache_control->hasMustRevalidate());

            // CC:no-cache (only if there are no parameters)
            const bool ccNoCacheNoParams = rep->cache_control->hasNoCacheWithoutParameters();

            // CC:s-maxage=N
            const bool ccSMaxAge = rep->cache_control->hasSMaxAge();

            // CC:private (yes, these can sometimes be stored)
            const bool ccPrivate = rep->cache_control->hasPrivate();

            if (ccNoCacheNoParams || ccPrivate)
                EBIT_SET(entry->flags, ENTRY_REVALIDATE_ALWAYS);
            else if (ccMustRevalidate || ccSMaxAge)
                EBIT_SET(entry->flags, ENTRY_REVALIDATE_STALE);
        }
#if USE_HTTP_VIOLATIONS // response header Pragma::no-cache is undefined in HTTP
        else {
            // Expensive calculation. So only do it IF the CC: header is not present.

            /* HACK: Pragma: no-cache in _replies_ is not documented in HTTP,
             * but servers like "Active Imaging Webcast/2.0" sure do use it */
            if (rep->header.has(Http::HdrType::PRAGMA) &&
                    rep->header.hasListMember(Http::HdrType::PRAGMA,"no-cache",','))
                EBIT_SET(entry->flags, ENTRY_REVALIDATE_ALWAYS);
        }
#endif
    }

#if HEADERS_LOG
    headersLog(1, 0, request->method, rep);

#endif

    ctx_exit(ctx);
}

HttpStateData::ConnectionStatus
HttpStateData::statusIfComplete() const
{
    const HttpReply *rep = virginReply();
    /** \par
     * If the reply wants to close the connection, it takes precedence */

    static SBuf close("close", 5);
    if (httpHeaderHasConnDir(&rep->header, close))
        return COMPLETE_NONPERSISTENT_MSG;

    /** \par
     * If we didn't send a keep-alive request header, then this
     * can not be a persistent connection.
     */
    if (!flags.keepalive)
        return COMPLETE_NONPERSISTENT_MSG;

    /** \par
     * If we haven't sent the whole request then this can not be a persistent
     * connection.
     */
    if (!flags.request_sent) {
        debugs(11, 2, "Request not yet fully sent " << request->method << ' ' << entry->url());
        return COMPLETE_NONPERSISTENT_MSG;
    }

    /** \par
     * What does the reply have to say about keep-alive?
     */
    /**
     \bug XXX BUG?
     * If the origin server (HTTP/1.0) does not send a keep-alive
     * header, but keeps the connection open anyway, what happens?
     * We'll return here and http.c waits for an EOF before changing
     * store_status to STORE_OK.   Combine this with ENTRY_FWD_HDR_WAIT
     * and an error status code, and we might have to wait until
     * the server times out the socket.
     */
    if (!rep->keep_alive)
        return COMPLETE_NONPERSISTENT_MSG;

    return COMPLETE_PERSISTENT_MSG;
}

HttpStateData::ConnectionStatus
HttpStateData::persistentConnStatus() const
{
    debugs(11, 3, HERE << serverConnection << " eof=" << eof);
    if (eof) // already reached EOF
        return COMPLETE_NONPERSISTENT_MSG;

    /* If server fd is closing (but we have not been notified yet), stop Comm
       I/O to avoid assertions. TODO: Change Comm API to handle callers that
       want more I/O after async closing (usually initiated by others). */
    // XXX: add canReceive or s/canSend/canTalkToServer/
    if (!Comm::IsConnOpen(serverConnection))
        return COMPLETE_NONPERSISTENT_MSG;

    /** \par
     * In chunked response we do not know the content length but we are absolutely
     * sure about the end of response, so we are calling the statusIfComplete to
     * decide if we can be persistant
     */
    if (lastChunk && flags.chunked)
        return statusIfComplete();

    const HttpReply *vrep = virginReply();
    debugs(11, 5, "persistentConnStatus: content_length=" << vrep->content_length);

    const int64_t clen = vrep->bodySize(request->method);

    debugs(11, 5, "persistentConnStatus: clen=" << clen);

    /* If the body size is unknown we must wait for EOF */
    if (clen < 0)
        return INCOMPLETE_MSG;

    /** \par
     * If the body size is known, we must wait until we've gotten all of it. */
    if (clen > 0) {
        debugs(11,5, "payloadSeen=" << payloadSeen << " content_length=" << vrep->content_length);

        if (payloadSeen < vrep->content_length)
            return INCOMPLETE_MSG;

        if (payloadTruncated > 0) // already read more than needed
            return COMPLETE_NONPERSISTENT_MSG; // disable pconns
    }

    /** \par
     * If there is no message body or we got it all, we can be persistent */
    return statusIfComplete();
}

static void
readDelayed(void *context, CommRead const &)
{
    HttpStateData *state = static_cast<HttpStateData*>(context);
    state->flags.do_next_read = true;
    state->maybeReadVirginBody();
}

void
HttpStateData::readReply(const CommIoCbParams &io)
{
    Must(!flags.do_next_read); // XXX: should have been set false by mayReadVirginBody()
    flags.do_next_read = false;

    debugs(11, 5, io.conn);

    // Bail out early on Comm::ERR_CLOSING - close handlers will tidy up for us
    if (io.flag == Comm::ERR_CLOSING) {
        debugs(11, 3, "http socket closing");
        return;
    }

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        abortTransaction("store entry aborted while reading reply");
        return;
    }

    Must(Comm::IsConnOpen(serverConnection));
    Must(io.conn->fd == serverConnection->fd);

    /*
     * Don't reset the timeout value here. The value should be
     * counting Config.Timeout.request and applies to the request
     * as a whole, not individual read() calls.
     * Plus, it breaks our lame *HalfClosed() detection
     */

    Must(maybeMakeSpaceAvailable(true));
    CommIoCbParams rd(this); // will be expanded with ReadNow results
    rd.conn = io.conn;
    rd.size = entry->bytesWanted(Range<size_t>(0, inBuf.spaceSize()));

    if (rd.size <= 0) {
        assert(entry->mem_obj);
        AsyncCall::Pointer nilCall;
        entry->mem_obj->delayRead(DeferredRead(readDelayed, this, CommRead(io.conn, NULL, 0, nilCall)));
        return;
    }

    switch (Comm::ReadNow(rd, inBuf)) {
    case Comm::INPROGRESS:
        if (inBuf.isEmpty())
            debugs(33, 2, io.conn << ": no data to process, " << xstrerr(rd.xerrno));
        flags.do_next_read = true;
        maybeReadVirginBody();
        return;

    case Comm::OK:
    {
        payloadSeen += rd.size;
#if USE_DELAY_POOLS
        DelayId delayId = entry->mem_obj->mostBytesAllowed();
        delayId.bytesIn(rd.size);
#endif

        statCounter.server.all.kbytes_in += rd.size;
        statCounter.server.http.kbytes_in += rd.size;
        ++ IOStats.Http.reads;

        int bin = 0;
        for (int clen = rd.size - 1; clen; ++bin)
            clen >>= 1;

        ++ IOStats.Http.read_hist[bin];

        request->hier.notePeerRead();
    }

        /* Continue to process previously read data */
    break;

    case Comm::ENDFILE: // close detected by 0-byte read
        eof = 1;
        flags.do_next_read = false;

        /* Continue to process previously read data */
        break;

    // case Comm::COMM_ERROR:
    default: // no other flags should ever occur
        debugs(11, 2, io.conn << ": read failure: " << xstrerr(rd.xerrno));
        const auto err = new ErrorState(ERR_READ_ERROR, Http::scBadGateway, fwd->request, fwd->al);
        err->xerrno = rd.xerrno;
        fwd->fail(err);
        flags.do_next_read = false;
        closeServer();
        mustStop("HttpStateData::readReply");
        return;
    }

    /* Process next response from buffer */
    processReply();
}

/// processes the already read and buffered response data, possibly after
/// waiting for asynchronous 1xx control message processing
void
HttpStateData::processReply()
{

    if (flags.handling1xx) { // we came back after handling a 1xx response
        debugs(11, 5, HERE << "done with 1xx handling");
        flags.handling1xx = false;
        Must(!flags.headers_parsed);
    }

    if (!flags.headers_parsed) { // have not parsed headers yet?
        PROF_start(HttpStateData_processReplyHeader);
        processReplyHeader();
        PROF_stop(HttpStateData_processReplyHeader);

        if (!continueAfterParsingHeader()) // parsing error or need more data
            return; // TODO: send errors to ICAP

        adaptOrFinalizeReply(); // may write to, abort, or "close" the entry
    }

    // kick more reads if needed and/or process the response body, if any
    PROF_start(HttpStateData_processReplyBody);
    processReplyBody(); // may call serverComplete()
    PROF_stop(HttpStateData_processReplyBody);
}

/**
 \retval true    if we can continue with processing the body or doing ICAP.
 */
bool
HttpStateData::continueAfterParsingHeader()
{
    if (flags.handling1xx) {
        debugs(11, 5, HERE << "wait for 1xx handling");
        Must(!flags.headers_parsed);
        return false;
    }

    if (!flags.headers_parsed && !eof) {
        debugs(11, 9, "needs more at " << inBuf.length());
        flags.do_next_read = true;
        /** \retval false If we have not finished parsing the headers and may get more data.
         *                Schedules more reads to retrieve the missing data.
         */
        maybeReadVirginBody(); // schedules all kinds of reads; TODO: rename
        return false;
    }

    /** If we are done with parsing, check for errors */

    err_type error = ERR_NONE;

    if (flags.headers_parsed) { // parsed headers, possibly with errors
        // check for header parsing errors
        if (HttpReply *vrep = virginReply()) {
            const Http::StatusCode s = vrep->sline.status();
            const AnyP::ProtocolVersion &v = vrep->sline.version;
            if (s == Http::scInvalidHeader && v != Http::ProtocolVersion(0,9)) {
                debugs(11, DBG_IMPORTANT, "WARNING: HTTP: Invalid Response: Bad header encountered from " << entry->url() << " AKA " << request->url);
                error = ERR_INVALID_RESP;
            } else if (s == Http::scHeaderTooLarge) {
                fwd->dontRetry(true);
                error = ERR_TOO_BIG;
            } else if (vrep->header.conflictingContentLength()) {
                fwd->dontRetry(true);
                error = ERR_INVALID_RESP;
            } else {
                return true; // done parsing, got reply, and no error
            }
        } else {
            // parsed headers but got no reply
            debugs(11, DBG_IMPORTANT, "WARNING: HTTP: Invalid Response: No reply at all for " << entry->url() << " AKA " << request->url);
            error = ERR_INVALID_RESP;
        }
    } else {
        assert(eof);
        if (inBuf.length()) {
            error = ERR_INVALID_RESP;
            debugs(11, DBG_IMPORTANT, "WARNING: HTTP: Invalid Response: Headers did not parse at all for " << entry->url() << " AKA " << request->url);
        } else {
            error = ERR_ZERO_SIZE_OBJECT;
            debugs(11, (request->flags.accelerated?DBG_IMPORTANT:2), "WARNING: HTTP: Invalid Response: No object data received for " << entry->url() << " AKA " << request->url);
        }
    }

    assert(error != ERR_NONE);
    entry->reset();
    fwd->fail(new ErrorState(error, Http::scBadGateway, fwd->request, fwd->al));
    flags.do_next_read = false;
    closeServer();
    mustStop("HttpStateData::continueAfterParsingHeader");
    return false; // quit on error
}

/** truncate what we read if we read too much so that writeReplyBody()
    writes no more than what we should have read */
void
HttpStateData::truncateVirginBody()
{
    assert(flags.headers_parsed);

    HttpReply *vrep = virginReply();
    int64_t clen = -1;
    if (!vrep->expectingBody(request->method, clen) || clen < 0)
        return; // no body or a body of unknown size, including chunked

    if (payloadSeen - payloadTruncated <= clen)
        return; // we did not read too much or already took care of the extras

    if (const int64_t extras = payloadSeen - payloadTruncated - clen) {
        // server sent more that the advertised content length
        debugs(11, 5, "payloadSeen=" << payloadSeen <<
               " clen=" << clen << '/' << vrep->content_length <<
               " trucated=" << payloadTruncated << '+' << extras);

        inBuf.chop(0, inBuf.length() - extras);
        payloadTruncated += extras;
    }
}

/**
 * Call this when there is data from the origin server
 * which should be sent to either StoreEntry, or to ICAP...
 */
void
HttpStateData::writeReplyBody()
{
    truncateVirginBody(); // if needed
    const char *data = inBuf.rawContent();
    int len = inBuf.length();
    addVirginReplyBody(data, len);
    inBuf.consume(len);
}

bool
HttpStateData::decodeAndWriteReplyBody()
{
    const char *data = NULL;
    int len;
    bool wasThereAnException = false;
    assert(flags.chunked);
    assert(httpChunkDecoder);
    SQUID_ENTER_THROWING_CODE();
    MemBuf decodedData;
    decodedData.init();
    httpChunkDecoder->setPayloadBuffer(&decodedData);
    const bool doneParsing = httpChunkDecoder->parse(inBuf);
    inBuf = httpChunkDecoder->remaining(); // sync buffers after parse
    len = decodedData.contentSize();
    data=decodedData.content();
    addVirginReplyBody(data, len);
    if (doneParsing) {
        lastChunk = 1;
        flags.do_next_read = false;
    }
    SQUID_EXIT_THROWING_CODE(wasThereAnException);
    return wasThereAnException;
}

/**
 * processReplyBody has two purposes:
 *  1 - take the reply body data, if any, and put it into either
 *      the StoreEntry, or give it over to ICAP.
 *  2 - see if we made it to the end of the response (persistent
 *      connections and such)
 */
void
HttpStateData::processReplyBody()
{
    if (!flags.headers_parsed) {
        flags.do_next_read = true;
        maybeReadVirginBody();
        return;
    }

#if USE_ADAPTATION
    debugs(11,5, HERE << "adaptationAccessCheckPending=" << adaptationAccessCheckPending);
    if (adaptationAccessCheckPending)
        return;

#endif

    /*
     * At this point the reply headers have been parsed and consumed.
     * That means header content has been removed from readBuf and
     * it contains only body data.
     */
    if (entry->isAccepting()) {
        if (flags.chunked) {
            if (!decodeAndWriteReplyBody()) {
                flags.do_next_read = false;
                serverComplete();
                return;
            }
        } else
            writeReplyBody();
    }

    // storing/sending methods like earlier adaptOrFinalizeReply() or
    // above writeReplyBody() may release/abort the store entry.
    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        // TODO: In some cases (e.g., 304), we should keep persistent conn open.
        // Detect end-of-reply (and, hence, pool our idle pconn) earlier (ASAP).
        abortTransaction("store entry aborted while storing reply");
        return;
    } else
        switch (persistentConnStatus()) {
        case INCOMPLETE_MSG: {
            debugs(11, 5, "processReplyBody: INCOMPLETE_MSG from " << serverConnection);
            /* Wait for more data or EOF condition */
            AsyncCall::Pointer nil;
            if (flags.keepalive_broken) {
                commSetConnTimeout(serverConnection, 10, nil);
            } else {
                commSetConnTimeout(serverConnection, Config.Timeout.read, nil);
            }

            flags.do_next_read = true;
        }
        break;

        case COMPLETE_PERSISTENT_MSG: {
            debugs(11, 5, "processReplyBody: COMPLETE_PERSISTENT_MSG from " << serverConnection);

            // TODO: Remove serverConnectionSaved but preserve exception safety.

            commUnsetConnTimeout(serverConnection);
            flags.do_next_read = false;

            comm_remove_close_handler(serverConnection->fd, closeHandler);
            closeHandler = NULL;

            Ip::Address client_addr; // XXX: Remove as unused. Why was it added?
            if (request->flags.spoofClientIp)
                client_addr = request->client_addr;

            auto serverConnectionSaved = serverConnection;
            fwd->unregister(serverConnection);
            serverConnection = nullptr;

            bool ispinned = false; // TODO: Rename to isOrShouldBePinned
            if (request->flags.pinned) {
                ispinned = true;
            } else if (request->flags.connectionAuth && request->flags.authSent) {
                ispinned = true;
            }

            if (ispinned) {
                if (request->clientConnectionManager.valid()) {
                    CallJobHere1(11, 4, request->clientConnectionManager,
                                 ConnStateData,
                                 notePinnedConnectionBecameIdle,
                                 ConnStateData::PinnedIdleContext(serverConnectionSaved, request));
                } else {
                    // must not pool/share ispinned connections, even orphaned ones
                    serverConnectionSaved->close();
                }
            } else {
                fwdPconnPool->push(serverConnectionSaved, request->url.host());
            }

            serverComplete();
            return;
        }

        case COMPLETE_NONPERSISTENT_MSG:
            debugs(11, 5, "processReplyBody: COMPLETE_NONPERSISTENT_MSG from " << serverConnection);
            serverComplete();
            return;
        }

    maybeReadVirginBody();
}

bool
HttpStateData::mayReadVirginReplyBody() const
{
    // TODO: Be more precise here. For example, if/when reading trailer, we may
    // not be doneWithServer() yet, but we should return false. Similarly, we
    // could still be writing the request body after receiving the whole reply.
    return !doneWithServer();
}

void
HttpStateData::maybeReadVirginBody()
{
    // too late to read
    if (!Comm::IsConnOpen(serverConnection) || fd_table[serverConnection->fd].closing())
        return;

    if (!maybeMakeSpaceAvailable(false))
        return;

    // XXX: get rid of the do_next_read flag
    // check for the proper reasons preventing read(2)
    if (!flags.do_next_read)
        return;

    flags.do_next_read = false;

    // must not already be waiting for read(2) ...
    assert(!Comm::MonitorsRead(serverConnection->fd));

    // wait for read(2) to be possible.
    typedef CommCbMemFunT<HttpStateData, CommIoCbParams> Dialer;
    AsyncCall::Pointer call = JobCallback(11, 5, Dialer, this, HttpStateData::readReply);
    Comm::Read(serverConnection, call);
}

bool
HttpStateData::maybeMakeSpaceAvailable(bool doGrow)
{
    // how much we are allowed to buffer
    const int limitBuffer = (flags.headers_parsed ? Config.readAheadGap : Config.maxReplyHeaderSize);

    if (limitBuffer < 0 || inBuf.length() >= (SBuf::size_type)limitBuffer) {
        // when buffer is at or over limit already
        debugs(11, 7, "will not read up to " << limitBuffer << ". buffer has (" << inBuf.length() << "/" << inBuf.spaceSize() << ") from " << serverConnection);
        debugs(11, DBG_DATA, "buffer has {" << inBuf << "}");
        // Process next response from buffer
        processReply();
        return false;
    }

    // how much we want to read
    const size_t read_size = calcBufferSpaceToReserve(inBuf.spaceSize(), (limitBuffer - inBuf.length()));

    if (!read_size) {
        debugs(11, 7, "will not read up to " << read_size << " into buffer (" << inBuf.length() << "/" << inBuf.spaceSize() << ") from " << serverConnection);
        return false;
    }

    // just report whether we could grow or not, do not actually do it
    if (doGrow)
        return (read_size >= 2);

    // we may need to grow the buffer
    inBuf.reserveSpace(read_size);
    debugs(11, 8, (!flags.do_next_read ? "will not" : "may") <<
           " read up to " << read_size << " bytes info buf(" << inBuf.length() << "/" << inBuf.spaceSize() <<
           ") from " << serverConnection);

    return (inBuf.spaceSize() >= 2); // only read if there is 1+ bytes of space available
}

/// called after writing the very last request byte (body, last-chunk, etc)
void
HttpStateData::wroteLast(const CommIoCbParams &io)
{
    debugs(11, 5, HERE << serverConnection << ": size " << io.size << ": errflag " << io.flag << ".");
#if URL_CHECKSUM_DEBUG

    entry->mem_obj->checkUrlChecksum();
#endif

    // XXX: Keep in sync with Client::sentRequestBody().
    // TODO: Extract common parts.

    if (io.size > 0) {
        fd_bytes(io.fd, io.size, FD_WRITE);
        statCounter.server.all.kbytes_out += io.size;
        statCounter.server.http.kbytes_out += io.size;
    }

    if (io.flag == Comm::ERR_CLOSING)
        return;

    // both successful and failed writes affect response times
    request->hier.notePeerWrite();

    if (io.flag) {
        const auto err = new ErrorState(ERR_WRITE_ERROR, Http::scBadGateway, fwd->request, fwd->al);
        err->xerrno = io.xerrno;
        fwd->fail(err);
        closeServer();
        mustStop("HttpStateData::wroteLast");
        return;
    }

    sendComplete();
}

/// successfully wrote the entire request (including body, last-chunk, etc.)
void
HttpStateData::sendComplete()
{
    /*
     * Set the read timeout here because it hasn't been set yet.
     * We only set the read timeout after the request has been
     * fully written to the peer.  If we start the timeout
     * after connection establishment, then we are likely to hit
     * the timeout for POST/PUT requests that have very large
     * request bodies.
     */
    typedef CommCbMemFunT<HttpStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(11, 5,
                                      TimeoutDialer, this, HttpStateData::httpTimeout);

    commSetConnTimeout(serverConnection, Config.Timeout.read, timeoutCall);
    flags.request_sent = true;
}

void
HttpStateData::closeServer()
{
    debugs(11,5, HERE << "closing HTTP server " << serverConnection << " this " << this);

    if (Comm::IsConnOpen(serverConnection)) {
        fwd->unregister(serverConnection);
        comm_remove_close_handler(serverConnection->fd, closeHandler);
        closeHandler = NULL;
        serverConnection->close();
    }
}

bool
HttpStateData::doneWithServer() const
{
    return !Comm::IsConnOpen(serverConnection);
}

/*
 * Fixup authentication request headers for special cases
 */
static void
httpFixupAuthentication(HttpRequest * request, const HttpHeader * hdr_in, HttpHeader * hdr_out, const Http::StateFlags &flags)
{
    /* Nothing to do unless we are forwarding to a peer */
    if (!flags.peering)
        return;

    // This request is going "through" rather than "to" our _peer.
    if (flags.tunneling)
        return;

    /* Needs to be explicitly enabled */
    if (!request->peer_login)
        return;

    const auto header = flags.toOrigin ? Http::HdrType::AUTHORIZATION : Http::HdrType::PROXY_AUTHORIZATION;
    /* Maybe already dealt with? */
    if (hdr_out->has(header))
        return;

    /* Nothing to do here for PASSTHRU */
    if (strcmp(request->peer_login, "PASSTHRU") == 0)
        return;

    // Dangerous and undocumented PROXYPASS is a single-signon to servers with
    // the proxy password. Only Basic Authentication can work this way. This
    // statement forwards a "basic" Proxy-Authorization value from our client
    // to an originserver peer. Other PROXYPASS cases are handled lower.
    if (flags.toOrigin &&
            strcmp(request->peer_login, "PROXYPASS") == 0 &&
            hdr_in->has(Http::HdrType::PROXY_AUTHORIZATION)) {

        const char *auth = hdr_in->getStr(Http::HdrType::PROXY_AUTHORIZATION);

        if (auth && strncasecmp(auth, "basic ", 6) == 0) {
            hdr_out->putStr(header, auth);
            return;
        }
    }

    char loginbuf[base64_encode_len(MAX_LOGIN_SZ)];
    size_t blen;
    struct base64_encode_ctx ctx;
    base64_encode_init(&ctx);

    /* Special mode to pass the username to the upstream cache */
    if (*request->peer_login == '*') {
        const char *username = "-";

        if (request->extacl_user.size())
            username = request->extacl_user.termedBuf();
#if USE_AUTH
        else if (request->auth_user_request != NULL)
            username = request->auth_user_request->username();
#endif

        blen = base64_encode_update(&ctx, loginbuf, strlen(username), reinterpret_cast<const uint8_t*>(username));
        blen += base64_encode_update(&ctx, loginbuf+blen, strlen(request->peer_login +1), reinterpret_cast<const uint8_t*>(request->peer_login +1));
        blen += base64_encode_final(&ctx, loginbuf+blen);
        httpHeaderPutStrf(hdr_out, header, "Basic %.*s", (int)blen, loginbuf);
        return;
    }

    /* external_acl provided credentials */
    if (request->extacl_user.size() && request->extacl_passwd.size() &&
            (strcmp(request->peer_login, "PASS") == 0 ||
             strcmp(request->peer_login, "PROXYPASS") == 0)) {

        blen = base64_encode_update(&ctx, loginbuf, request->extacl_user.size(), reinterpret_cast<const uint8_t*>(request->extacl_user.rawBuf()));
        blen += base64_encode_update(&ctx, loginbuf+blen, 1, reinterpret_cast<const uint8_t*>(":"));
        blen += base64_encode_update(&ctx, loginbuf+blen, request->extacl_passwd.size(), reinterpret_cast<const uint8_t*>(request->extacl_passwd.rawBuf()));
        blen += base64_encode_final(&ctx, loginbuf+blen);
        httpHeaderPutStrf(hdr_out, header, "Basic %.*s", (int)blen, loginbuf);
        return;
    }
    // if no external user credentials are available to fake authentication with PASS acts like PASSTHRU
    if (strcmp(request->peer_login, "PASS") == 0)
        return;

    /* Kerberos login to peer */
#if HAVE_AUTH_MODULE_NEGOTIATE && HAVE_KRB5 && HAVE_GSSAPI
    if (strncmp(request->peer_login, "NEGOTIATE",strlen("NEGOTIATE")) == 0) {
        char *Token=NULL;
        char *PrincipalName=NULL,*p;
        int negotiate_flags = 0;

        if ((p=strchr(request->peer_login,':')) != NULL ) {
            PrincipalName=++p;
        }
        if (request->flags.auth_no_keytab) {
            negotiate_flags |= PEER_PROXY_NEGOTIATE_NOKEYTAB;
        }
        Token = peer_proxy_negotiate_auth(PrincipalName, request->peer_host, negotiate_flags);
        if (Token) {
            httpHeaderPutStrf(hdr_out, header, "Negotiate %s",Token);
        }
        return;
    }
#endif /* HAVE_KRB5 && HAVE_GSSAPI */

    blen = base64_encode_update(&ctx, loginbuf, strlen(request->peer_login), reinterpret_cast<const uint8_t*>(request->peer_login));
    blen += base64_encode_final(&ctx, loginbuf+blen);
    httpHeaderPutStrf(hdr_out, header, "Basic %.*s", (int)blen, loginbuf);
    return;
}

/*
 * build request headers and append them to a given MemBuf
 * used by buildRequestPrefix()
 * note: initialised the HttpHeader, the caller is responsible for Clean()-ing
 */
void
HttpStateData::httpBuildRequestHeader(HttpRequest * request,
                                      StoreEntry * entry,
                                      const AccessLogEntryPointer &al,
                                      HttpHeader * hdr_out,
                                      const Http::StateFlags &flags)
{
    /* building buffer for complex strings */
#define BBUF_SZ (MAX_URL+32)
    LOCAL_ARRAY(char, bbuf, BBUF_SZ);
    LOCAL_ARRAY(char, ntoabuf, MAX_IPSTRLEN);
    const HttpHeader *hdr_in = &request->header;
    const HttpHeaderEntry *e = NULL;
    HttpHeaderPos pos = HttpHeaderInitPos;
    assert (hdr_out->owner == hoRequest);

    /* use our IMS header if the cached entry has Last-Modified time */
    if (request->lastmod > -1)
        hdr_out->putTime(Http::HdrType::IF_MODIFIED_SINCE, request->lastmod);

    // Add our own If-None-Match field if the cached entry has a strong ETag.
    // copyOneHeaderFromClientsideRequestToUpstreamRequest() adds client ones.
    if (request->etag.size() > 0) {
        hdr_out->addEntry(new HttpHeaderEntry(Http::HdrType::IF_NONE_MATCH, SBuf(),
                                              request->etag.termedBuf()));
    }

    bool we_do_ranges = decideIfWeDoRanges (request);

    String strConnection (hdr_in->getList(Http::HdrType::CONNECTION));

    while ((e = hdr_in->getEntry(&pos)))
        copyOneHeaderFromClientsideRequestToUpstreamRequest(e, strConnection, request, hdr_out, we_do_ranges, flags);

    /* Abstraction break: We should interpret multipart/byterange responses
     * into offset-length data, and this works around our inability to do so.
     */
    if (!we_do_ranges && request->multipartRangeRequest()) {
        /* don't cache the result */
        request->flags.cachable = false;
        /* pretend it's not a range request */
        request->ignoreRange("want to request the whole object");
        request->flags.isRanged = false;
    }

    hdr_out->addVia(request->http_ver, hdr_in);

    if (request->flags.accelerated) {
        /* Append Surrogate-Capabilities */
        String strSurrogate(hdr_in->getList(Http::HdrType::SURROGATE_CAPABILITY));
#if USE_SQUID_ESI
        snprintf(bbuf, BBUF_SZ, "%s=\"Surrogate/1.0 ESI/1.0\"", Config.Accel.surrogate_id);
#else
        snprintf(bbuf, BBUF_SZ, "%s=\"Surrogate/1.0\"", Config.Accel.surrogate_id);
#endif
        strListAdd(&strSurrogate, bbuf, ',');
        hdr_out->putStr(Http::HdrType::SURROGATE_CAPABILITY, strSurrogate.termedBuf());
    }

    /** \pre Handle X-Forwarded-For */
    if (strcmp(opt_forwarded_for, "delete") != 0) {

        String strFwd = hdr_in->getList(Http::HdrType::X_FORWARDED_FOR);

        // if we cannot double strFwd size, then it grew past 50% of the limit
        if (!strFwd.canGrowBy(strFwd.size())) {
            // There is probably a forwarding loop with Via detection disabled.
            // If we do nothing, String will assert on overflow soon.
            // TODO: Terminate all transactions with huge XFF?
            strFwd = "error";

            static int warnedCount = 0;
            if (warnedCount++ < 100) {
                const SBuf url(entry ? SBuf(entry->url()) : request->effectiveRequestUri());
                debugs(11, DBG_IMPORTANT, "Warning: likely forwarding loop with " << url);
            }
        }

        if (strcmp(opt_forwarded_for, "on") == 0) {
            /** If set to ON - append client IP or 'unknown'. */
            if ( request->client_addr.isNoAddr() )
                strListAdd(&strFwd, "unknown", ',');
            else
                strListAdd(&strFwd, request->client_addr.toStr(ntoabuf, MAX_IPSTRLEN), ',');
        } else if (strcmp(opt_forwarded_for, "off") == 0) {
            /** If set to OFF - append 'unknown'. */
            strListAdd(&strFwd, "unknown", ',');
        } else if (strcmp(opt_forwarded_for, "transparent") == 0) {
            /** If set to TRANSPARENT - pass through unchanged. */
        } else if (strcmp(opt_forwarded_for, "truncate") == 0) {
            /** If set to TRUNCATE - drop existing list and replace with client IP or 'unknown'. */
            if ( request->client_addr.isNoAddr() )
                strFwd = "unknown";
            else
                strFwd = request->client_addr.toStr(ntoabuf, MAX_IPSTRLEN);
        }
        if (strFwd.size() > 0)
            hdr_out->putStr(Http::HdrType::X_FORWARDED_FOR, strFwd.termedBuf());
    }
    /** If set to DELETE - do not copy through. */

    /* append Host if not there already */
    if (!hdr_out->has(Http::HdrType::HOST)) {
        if (request->peer_domain) {
            hdr_out->putStr(Http::HdrType::HOST, request->peer_domain);
        } else {
            SBuf authority = request->url.authority();
            hdr_out->putStr(Http::HdrType::HOST, authority.c_str());
        }
    }

    /* append Authorization if known in URL, not in header and going direct */
    if (!hdr_out->has(Http::HdrType::AUTHORIZATION)) {
        if (flags.toOrigin && !request->url.userInfo().isEmpty()) {
            static char result[base64_encode_len(MAX_URL*2)]; // should be big enough for a single URI segment
            struct base64_encode_ctx ctx;
            base64_encode_init(&ctx);
            size_t blen = base64_encode_update(&ctx, result, request->url.userInfo().length(), reinterpret_cast<const uint8_t*>(request->url.userInfo().rawContent()));
            blen += base64_encode_final(&ctx, result+blen);
            result[blen] = '\0';
            if (blen)
                httpHeaderPutStrf(hdr_out, Http::HdrType::AUTHORIZATION, "Basic %.*s", (int)blen, result);
        }
    }

    /* Fixup (Proxy-)Authorization special cases. Plain relaying dealt with above */
    httpFixupAuthentication(request, hdr_in, hdr_out, flags);

    /* append Cache-Control, add max-age if not there already */
    {
        HttpHdrCc *cc = hdr_in->getCc();

        if (!cc)
            cc = new HttpHdrCc();

#if 0 /* see bug 2330 */
        /* Set no-cache if determined needed but not found */
        if (request->flags.nocache)
            EBIT_SET(cc->mask, HttpHdrCcType::CC_NO_CACHE);
#endif

        /* Add max-age only without no-cache */
        if (!cc->hasMaxAge() && !cc->hasNoCache()) {
            // XXX: performance regression. c_str() reallocates
            SBuf tmp(request->effectiveRequestUri());
            cc->maxAge(getMaxAge(entry ? entry->url() : tmp.c_str()));
        }

        /* Enforce sibling relations */
        if (flags.only_if_cached)
            cc->onlyIfCached(true);

        hdr_out->putCc(cc);

        delete cc;
    }

    // Always send Connection because HTTP/1.0 servers need explicit "keep-alive"
    // while HTTP/1.1 servers need explicit "close", and we do not always know
    // the server expectations.
    hdr_out->putStr(Http::HdrType::CONNECTION, flags.keepalive ? "keep-alive" : "close");

    /* append Front-End-Https */
    if (flags.front_end_https) {
        if (flags.front_end_https == 1 || request->url.getScheme() == AnyP::PROTO_HTTPS)
            hdr_out->putStr(Http::HdrType::FRONT_END_HTTPS, "On");
    }

    if (flags.chunked_request) {
        // Do not just copy the original value so that if the client-side
        // starts decode other encodings, this code may remain valid.
        hdr_out->putStr(Http::HdrType::TRANSFER_ENCODING, "chunked");
    }

    /* Now mangle the headers. */
    httpHdrMangleList(hdr_out, request, al, ROR_REQUEST);

    strConnection.clean();
}

/**
 * Decides whether a particular header may be cloned from the received Clients request
 * to our outgoing fetch request.
 */
void
copyOneHeaderFromClientsideRequestToUpstreamRequest(const HttpHeaderEntry *e, const String strConnection, const HttpRequest * request, HttpHeader * hdr_out, const int we_do_ranges, const Http::StateFlags &flags)
{
    debugs(11, 5, "httpBuildRequestHeader: " << e->name << ": " << e->value );

    switch (e->id) {

    /** \par RFC 2616 sect 13.5.1 - Hop-by-Hop headers which Squid should not pass on. */

    case Http::HdrType::PROXY_AUTHORIZATION:
        /** \par Proxy-Authorization:
         * Only pass on proxy authentication to peers for which
         * authentication forwarding is explicitly enabled
         */
        if (!flags.toOrigin && request->peer_login &&
                (strcmp(request->peer_login, "PASS") == 0 ||
                 strcmp(request->peer_login, "PROXYPASS") == 0 ||
                 strcmp(request->peer_login, "PASSTHRU") == 0)) {
            hdr_out->addEntry(e->clone());
        }
        break;

    /** \par RFC 2616 sect 13.5.1 - Hop-by-Hop headers which Squid does not pass on. */

    case Http::HdrType::CONNECTION:          /** \par Connection: */
    case Http::HdrType::TE:                  /** \par TE: */
    case Http::HdrType::KEEP_ALIVE:          /** \par Keep-Alive: */
    case Http::HdrType::PROXY_AUTHENTICATE:  /** \par Proxy-Authenticate: */
    case Http::HdrType::TRAILER:             /** \par Trailer: */
    case Http::HdrType::UPGRADE:             /** \par Upgrade: */
    case Http::HdrType::TRANSFER_ENCODING:   /** \par Transfer-Encoding: */
        break;

    /** \par OTHER headers I haven't bothered to track down yet. */

    case Http::HdrType::AUTHORIZATION:
        /** \par WWW-Authorization:
         * Pass on WWW authentication */

        if (!flags.toOriginPeer()) {
            hdr_out->addEntry(e->clone());
        } else {
            /** \note Assume that talking to a cache_peer originserver makes
             * us a reverse proxy and only forward authentication if enabled
             * (see also httpFixupAuthentication for special cases)
             */
            if (request->peer_login &&
                    (strcmp(request->peer_login, "PASS") == 0 ||
                     strcmp(request->peer_login, "PASSTHRU") == 0 ||
                     strcmp(request->peer_login, "PROXYPASS") == 0)) {
                hdr_out->addEntry(e->clone());
            }
        }

        break;

    case Http::HdrType::HOST:
        /** \par Host:
         * Normally Squid rewrites the Host: header.
         * However, there is one case when we don't: If the URL
         * went through our redirector and the admin configured
         * 'redir_rewrites_host' to be off.
         */
        if (request->peer_domain)
            hdr_out->putStr(Http::HdrType::HOST, request->peer_domain);
        else if (request->flags.redirected && !Config.onoff.redir_rewrites_host)
            hdr_out->addEntry(e->clone());
        else {
            SBuf authority = request->url.authority();
            hdr_out->putStr(Http::HdrType::HOST, authority.c_str());
        }

        break;

    case Http::HdrType::IF_MODIFIED_SINCE:
        /** \par If-Modified-Since:
         * append unless we added our own,
         * but only if cache_miss_revalidate is enabled, or
         *  the request is not cacheable, or
         *  the request contains authentication credentials.
         * \note at most one client's If-Modified-Since header can pass through
         */
        // XXX: need to check and cleanup the auth case so cacheable auth requests get cached.
        if (hdr_out->has(Http::HdrType::IF_MODIFIED_SINCE))
            break;
        else if (Config.onoff.cache_miss_revalidate || !request->flags.cachable || request->flags.auth)
            hdr_out->addEntry(e->clone());
        break;

    case Http::HdrType::IF_NONE_MATCH:
        /** \par If-None-Match:
         * append if the wildcard '*' special case value is present, or
         *   cache_miss_revalidate is disabled, or
         *   the request is not cacheable in this proxy, or
         *   the request contains authentication credentials.
         * \note this header lists a set of responses for the server to elide sending. Squid added values are extending that set.
         */
        // XXX: need to check and cleanup the auth case so cacheable auth requests get cached.
        if (hdr_out->hasListMember(Http::HdrType::IF_MATCH, "*", ',') || Config.onoff.cache_miss_revalidate || !request->flags.cachable || request->flags.auth)
            hdr_out->addEntry(e->clone());
        break;

    case Http::HdrType::MAX_FORWARDS:
        /** \par Max-Forwards:
         * pass only on TRACE or OPTIONS requests */
        if (request->method == Http::METHOD_TRACE || request->method == Http::METHOD_OPTIONS) {
            const int64_t hops = e->getInt64();

            if (hops > 0)
                hdr_out->putInt64(Http::HdrType::MAX_FORWARDS, hops - 1);
        }

        break;

    case Http::HdrType::VIA:
        /** \par Via:
         * If Via is disabled then forward any received header as-is.
         * Otherwise leave for explicit updated addition later. */

        if (!Config.onoff.via)
            hdr_out->addEntry(e->clone());

        break;

    case Http::HdrType::RANGE:

    case Http::HdrType::IF_RANGE:

    case Http::HdrType::REQUEST_RANGE:
        /** \par Range:, If-Range:, Request-Range:
         * Only pass if we accept ranges */
        if (!we_do_ranges)
            hdr_out->addEntry(e->clone());

        break;

    case Http::HdrType::PROXY_CONNECTION: // SHOULD ignore. But doing so breaks things.
        break;

    case Http::HdrType::CONTENT_LENGTH:
        // pass through unless we chunk; also, keeping this away from default
        // prevents request smuggling via Connection: Content-Length tricks
        if (!flags.chunked_request)
            hdr_out->addEntry(e->clone());
        break;

    case Http::HdrType::X_FORWARDED_FOR:

    case Http::HdrType::CACHE_CONTROL:
        /** \par X-Forwarded-For:, Cache-Control:
         * handled specially by Squid, so leave off for now.
         * append these after the loop if needed */
        break;

    case Http::HdrType::FRONT_END_HTTPS:
        /** \par Front-End-Https:
         * Pass thru only if peer is configured with front-end-https */
        if (!flags.front_end_https)
            hdr_out->addEntry(e->clone());

        break;

    default:
        /** \par default.
         * pass on all other header fields
         * which are NOT listed by the special Connection: header. */
        if (strConnection.size()>0 && strListIsMember(&strConnection, e->name, ',')) {
            debugs(11, 2, "'" << e->name << "' header cropped by Connection: definition");
            return;
        }

        hdr_out->addEntry(e->clone());
    }
}

bool
HttpStateData::decideIfWeDoRanges (HttpRequest * request)
{
    bool result = true;
    /* decide if we want to do Ranges ourselves
     * and fetch the whole object now)
     * We want to handle Ranges ourselves iff
     *    - we can actually parse client Range specs
     *    - the specs are expected to be simple enough (e.g. no out-of-order ranges)
     *    - reply will be cachable
     * (If the reply will be uncachable we have to throw it away after
     *  serving this request, so it is better to forward ranges to
     *  the server and fetch only the requested content)
     */

    int64_t roffLimit = request->getRangeOffsetLimit();

    if (NULL == request->range || !request->flags.cachable
            || request->range->offsetLimitExceeded(roffLimit) || request->flags.connectionAuth)
        result = false;

    debugs(11, 8, "decideIfWeDoRanges: range specs: " <<
           request->range << ", cachable: " <<
           request->flags.cachable << "; we_do_ranges: " << result);

    return result;
}

/* build request prefix and append it to a given MemBuf;
 * return the length of the prefix */
mb_size_t
HttpStateData::buildRequestPrefix(MemBuf * mb)
{
    const int offset = mb->size;
    /* Uses a local httpver variable to print the HTTP label
     * since the HttpRequest may have an older version label.
     * XXX: This could create protocol bugs as the headers sent and
     * flow control should all be based on the HttpRequest version
     * not the one we are sending. Needs checking.
     */
    const AnyP::ProtocolVersion httpver = Http::ProtocolVersion();
    const SBuf url(flags.toOrigin ? request->url.path() : request->effectiveRequestUri());
    mb->appendf(SQUIDSBUFPH " " SQUIDSBUFPH " %s/%d.%d\r\n",
                SQUIDSBUFPRINT(request->method.image()),
                SQUIDSBUFPRINT(url),
                AnyP::ProtocolType_str[httpver.protocol],
                httpver.major,httpver.minor);
    /* build and pack headers */
    {
        HttpHeader hdr(hoRequest);
        httpBuildRequestHeader(request.getRaw(), entry, fwd->al, &hdr, flags);

        if (request->flags.pinned && request->flags.connectionAuth)
            request->flags.authSent = true;
        else if (hdr.has(Http::HdrType::AUTHORIZATION))
            request->flags.authSent = true;

        hdr.packInto(mb);
        hdr.clean();
    }
    /* append header terminator */
    mb->append(crlf, 2);
    return mb->size - offset;
}

/* This will be called when connect completes. Write request. */
bool
HttpStateData::sendRequest()
{
    MemBuf mb;

    debugs(11, 5, HERE << serverConnection << ", request " << request << ", this " << this << ".");

    if (!Comm::IsConnOpen(serverConnection)) {
        debugs(11,3, HERE << "cannot send request to closing " << serverConnection);
        assert(closeHandler != NULL);
        return false;
    }

    typedef CommCbMemFunT<HttpStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(11, 5,
                                      TimeoutDialer, this, HttpStateData::httpTimeout);
    commSetConnTimeout(serverConnection, Config.Timeout.lifetime, timeoutCall);
    flags.do_next_read = true;
    maybeReadVirginBody();

    if (request->body_pipe != NULL) {
        if (!startRequestBodyFlow()) // register to receive body data
            return false;
        typedef CommCbMemFunT<HttpStateData, CommIoCbParams> Dialer;
        requestSender = JobCallback(11,5,
                                    Dialer, this, HttpStateData::sentRequestBody);

        Must(!flags.chunked_request);
        // use chunked encoding if we do not know the length
        if (request->content_length < 0)
            flags.chunked_request = true;
    } else {
        assert(!requestBodySource);
        typedef CommCbMemFunT<HttpStateData, CommIoCbParams> Dialer;
        requestSender = JobCallback(11,5,
                                    Dialer, this,  HttpStateData::wroteLast);
    }

    /*
     * Is keep-alive okay for all request methods?
     */
    if (request->flags.mustKeepalive)
        flags.keepalive = true;
    else if (request->flags.pinned)
        flags.keepalive = request->persistent();
    else if (!Config.onoff.server_pconns)
        flags.keepalive = false;
    else if (flags.tunneling)
        // tunneled non pinned bumped requests must not keepalive
        flags.keepalive = !request->flags.sslBumped;
    else if (_peer == NULL)
        flags.keepalive = true;
    else if (_peer->stats.n_keepalives_sent < 10)
        flags.keepalive = true;
    else if ((double) _peer->stats.n_keepalives_recv /
             (double) _peer->stats.n_keepalives_sent > 0.50)
        flags.keepalive = true;

    if (_peer && !flags.tunneling) {
        /*The old code here was
          if (neighborType(_peer, request->url) == PEER_SIBLING && ...
          which is equivalent to:
          if (neighborType(_peer, URL()) == PEER_SIBLING && ...
          or better:
          if (((_peer->type == PEER_MULTICAST && p->options.mcast_siblings) ||
                 _peer->type == PEER_SIBLINGS ) && _peer->options.allow_miss)
               flags.only_if_cached = 1;

           But I suppose it was a bug
         */
        if (neighborType(_peer, request->url) == PEER_SIBLING && !_peer->options.allow_miss)
            flags.only_if_cached = true;

        flags.front_end_https = _peer->front_end_https;
    }

    mb.init();
    request->peer_host=_peer?_peer->host:NULL;
    buildRequestPrefix(&mb);

    debugs(11, 2, "HTTP Server " << serverConnection);
    debugs(11, 2, "HTTP Server REQUEST:\n---------\n" << mb.buf << "\n----------");

    Comm::Write(serverConnection, &mb, requestSender);
    return true;
}

bool
HttpStateData::getMoreRequestBody(MemBuf &buf)
{
    // parent's implementation can handle the no-encoding case
    if (!flags.chunked_request)
        return Client::getMoreRequestBody(buf);

    MemBuf raw;

    Must(requestBodySource != NULL);
    if (!requestBodySource->getMoreData(raw))
        return false; // no request body bytes to chunk yet

    // optimization: pre-allocate buffer size that should be enough
    const mb_size_t rawDataSize = raw.contentSize();
    // we may need to send: hex-chunk-size CRLF raw-data CRLF last-chunk
    buf.init(16 + 2 + rawDataSize + 2 + 5, raw.max_capacity);

    buf.appendf("%x\r\n", static_cast<unsigned int>(rawDataSize));
    buf.append(raw.content(), rawDataSize);
    buf.append("\r\n", 2);

    Must(rawDataSize > 0); // we did not accidently created last-chunk above

    // Do not send last-chunk unless we successfully received everything
    if (receivedWholeRequestBody) {
        Must(!flags.sentLastChunk);
        flags.sentLastChunk = true;
        buf.append("0\r\n\r\n", 5);
    }

    return true;
}

void
httpStart(FwdState *fwd)
{
    debugs(11, 3, fwd->request->method << ' ' << fwd->entry->url());
    AsyncJob::Start(new HttpStateData(fwd));
}

void
HttpStateData::start()
{
    if (!sendRequest()) {
        debugs(11, 3, "httpStart: aborted");
        mustStop("HttpStateData::start failed");
        return;
    }

    ++ statCounter.server.all.requests;
    ++ statCounter.server.http.requests;

    /*
     * We used to set the read timeout here, but not any more.
     * Now its set in httpSendComplete() after the full request,
     * including request body, has been written to the server.
     */
}

/// if broken posts are enabled for the request, try to fix and return true
bool
HttpStateData::finishingBrokenPost()
{
#if USE_HTTP_VIOLATIONS
    if (!Config.accessList.brokenPosts) {
        debugs(11, 5, HERE << "No brokenPosts list");
        return false;
    }

    ACLFilledChecklist ch(Config.accessList.brokenPosts, originalRequest().getRaw());
    ch.al = fwd->al;
    ch.syncAle(originalRequest().getRaw(), nullptr);
    if (!ch.fastCheck().allowed()) {
        debugs(11, 5, HERE << "didn't match brokenPosts");
        return false;
    }

    if (!Comm::IsConnOpen(serverConnection)) {
        debugs(11, 3, HERE << "ignoring broken POST for closed " << serverConnection);
        assert(closeHandler != NULL);
        return true; // prevent caller from proceeding as if nothing happened
    }

    debugs(11, 3, "finishingBrokenPost: fixing broken POST");
    typedef CommCbMemFunT<HttpStateData, CommIoCbParams> Dialer;
    requestSender = JobCallback(11,5,
                                Dialer, this, HttpStateData::wroteLast);
    Comm::Write(serverConnection, "\r\n", 2, requestSender, NULL);
    return true;
#else
    return false;
#endif /* USE_HTTP_VIOLATIONS */
}

/// if needed, write last-chunk to end the request body and return true
bool
HttpStateData::finishingChunkedRequest()
{
    if (flags.sentLastChunk) {
        debugs(11, 5, HERE << "already sent last-chunk");
        return false;
    }

    Must(receivedWholeRequestBody); // or we should not be sending last-chunk
    flags.sentLastChunk = true;

    typedef CommCbMemFunT<HttpStateData, CommIoCbParams> Dialer;
    requestSender = JobCallback(11,5, Dialer, this, HttpStateData::wroteLast);
    Comm::Write(serverConnection, "0\r\n\r\n", 5, requestSender, NULL);
    return true;
}

void
HttpStateData::doneSendingRequestBody()
{
    Client::doneSendingRequestBody();
    debugs(11,5, HERE << serverConnection);

    // do we need to write something after the last body byte?
    if (flags.chunked_request && finishingChunkedRequest())
        return;
    if (!flags.chunked_request && finishingBrokenPost())
        return;

    sendComplete();
}

// more origin request body data is available
void
HttpStateData::handleMoreRequestBodyAvailable()
{
    if (eof || !Comm::IsConnOpen(serverConnection)) {
        // XXX: we should check this condition in other callbacks then!
        // TODO: Check whether this can actually happen: We should unsubscribe
        // as a body consumer when the above condition(s) are detected.
        debugs(11, DBG_IMPORTANT, HERE << "Transaction aborted while reading HTTP body");
        return;
    }

    assert(requestBodySource != NULL);

    if (requestBodySource->buf().hasContent()) {
        // XXX: why does not this trigger a debug message on every request?

        if (flags.headers_parsed && !flags.abuse_detected) {
            flags.abuse_detected = true;
            debugs(11, DBG_IMPORTANT, "http handleMoreRequestBodyAvailable: Likely proxy abuse detected '" << request->client_addr << "' -> '" << entry->url() << "'" );

            if (virginReply()->sline.status() == Http::scInvalidHeader) {
                closeServer();
                mustStop("HttpStateData::handleMoreRequestBodyAvailable");
                return;
            }
        }
    }

    HttpStateData::handleMoreRequestBodyAvailable();
}

// premature end of the request body
void
HttpStateData::handleRequestBodyProducerAborted()
{
    Client::handleRequestBodyProducerAborted();
    if (entry->isEmpty()) {
        debugs(11, 3, "request body aborted: " << serverConnection);
        // We usually get here when ICAP REQMOD aborts during body processing.
        // We might also get here if client-side aborts, but then our response
        // should not matter because either client-side will provide its own or
        // there will be no response at all (e.g., if the the client has left).
        const auto err = new ErrorState(ERR_ICAP_FAILURE, Http::scInternalServerError, fwd->request, fwd->al);
        err->detailError(ERR_DETAIL_SRV_REQMOD_REQ_BODY);
        fwd->fail(err);
    }

    abortTransaction("request body producer aborted");
}

// called when we wrote request headers(!) or a part of the body
void
HttpStateData::sentRequestBody(const CommIoCbParams &io)
{
    if (io.size > 0)
        statCounter.server.http.kbytes_out += io.size;

    Client::sentRequestBody(io);
}

void
HttpStateData::abortAll(const char *reason)
{
    debugs(11,5, HERE << "aborting transaction for " << reason <<
           "; " << serverConnection << ", this " << this);
    mustStop(reason);
}

HttpStateData::ReuseDecision::ReuseDecision(const StoreEntry *e, const Http::StatusCode code)
    : answer(HttpStateData::ReuseDecision::reuseNot), reason(nullptr), entry(e), statusCode(code) {}

HttpStateData::ReuseDecision::Answers
HttpStateData::ReuseDecision::make(const HttpStateData::ReuseDecision::Answers ans, const char *why)
{
    answer = ans;
    reason = why;
    return answer;
}

std::ostream &operator <<(std::ostream &os, const HttpStateData::ReuseDecision &d)
{
    static const char *ReuseMessages[] = {
        "do not cache and do not share", // reuseNot
        "cache positively and share", // cachePositively
        "cache negatively and share", // cacheNegatively
        "do not cache but share" // doNotCacheButShare
    };

    assert(d.answer >= HttpStateData::ReuseDecision::reuseNot &&
           d.answer <= HttpStateData::ReuseDecision::doNotCacheButShare);
    return os << ReuseMessages[d.answer] << " because " << d.reason <<
           "; HTTP status " << d.statusCode << " " << *(d.entry);
}

