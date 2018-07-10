/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 58    HTTP Reply (Response) */

#include "squid.h"
#include "acl/AclSizeLimit.h"
#include "acl/FilledChecklist.h"
#include "globals.h"
#include "HttpBody.h"
#include "HttpHdrCc.h"
#include "HttpHdrContRange.h"
#include "HttpHdrSc.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "Store.h"
#include "StrList.h"

HttpReply::HttpReply():
    HttpMsg(hoReply),
    date(0),
    last_modified(0),
    expires(0),
    surrogate_control(nullptr),
    keep_alive(0),
    protoPrefix("HTTP/"),
    bodySizeMax(-2),
    content_range(nullptr)
{
    init();
}

HttpReply::~HttpReply()
{
    if (do_clean)
        clean();
}

void
HttpReply::init()
{
    hdrCacheInit();
    sline.init();
    pstate = psReadyToParseStartLine;
    do_clean = true;
}

void HttpReply::reset()
{

    // reset should not reset the protocol; could have made protoPrefix a
    // virtual function instead, but it is not clear whether virtual methods
    // are allowed with MEMPROXY_CLASS() and whether some cbdata void*
    // conversions are not going to kill virtual tables
    const String pfx = protoPrefix;
    clean();
    init();
    protoPrefix = pfx;
}

void
HttpReply::clean()
{
    // we used to assert that the pipe is NULL, but now the message only
    // points to a pipe that is owned and initiated by another object.
    body_pipe = NULL;

    body.clear();
    hdrCacheClean();
    header.clean();
    sline.clean();
    bodySizeMax = -2; // hack: make calculatedBodySizeMax() false
}

void
HttpReply::packHeadersInto(Packer * p) const
{
    sline.packInto(p);
    header.packInto(p);
    packerAppend(p, "\r\n", 2);
}

void
HttpReply::packInto(Packer * p)
{
    packHeadersInto(p);
    body.packInto(p);
}

/* create memBuf, create mem-based packer, pack, destroy packer, return MemBuf */
MemBuf *
HttpReply::pack()
{
    MemBuf *mb = new MemBuf;
    Packer p;

    mb->init();
    packerToMemInit(&p, mb);
    packInto(&p);
    packerClean(&p);
    return mb;
}

HttpReply *
HttpReply::make304() const
{
    static const http_hdr_type ImsEntries[] = {HDR_DATE, HDR_CONTENT_TYPE, HDR_EXPIRES, HDR_LAST_MODIFIED, /* eof */ HDR_OTHER};

    HttpReply *rv = new HttpReply;
    int t;
    HttpHeaderEntry *e;

    /* rv->content_length; */
    rv->date = date;
    rv->last_modified = last_modified;
    rv->expires = expires;
    rv->content_type = content_type;
    /* rv->content_range */
    /* rv->keep_alive */
    rv->sline.set(Http::ProtocolVersion(1,1), Http::scNotModified, NULL);

    for (t = 0; ImsEntries[t] != HDR_OTHER; ++t)
        if ((e = header.findEntry(ImsEntries[t])))
            rv->header.addEntry(e->clone());

    rv->putCc(cache_control);

    /* rv->body */
    return rv;
}

MemBuf *
HttpReply::packed304Reply()
{
    /* Not as efficient as skipping the header duplication,
     * but easier to maintain
     */
    HttpReply *temp = make304();
    MemBuf *rv = temp->pack();
    delete temp;
    return rv;
}

void
HttpReply::setHeaders(Http::StatusCode status, const char *reason,
                      const char *ctype, int64_t clen, time_t lmt, time_t expiresTime)
{
    HttpHeader *hdr;
    sline.set(Http::ProtocolVersion(1,1), status, reason);
    hdr = &header;
    hdr->putStr(HDR_SERVER, visible_appname_string);
    hdr->putStr(HDR_MIME_VERSION, "1.0");
    hdr->putTime(HDR_DATE, squid_curtime);

    if (ctype) {
        hdr->putStr(HDR_CONTENT_TYPE, ctype);
        content_type = ctype;
    } else
        content_type = String();

    if (clen >= 0)
        hdr->putInt64(HDR_CONTENT_LENGTH, clen);

    if (expiresTime >= 0)
        hdr->putTime(HDR_EXPIRES, expiresTime);

    if (lmt > 0)        /* this used to be lmt != 0 @?@ */
        hdr->putTime(HDR_LAST_MODIFIED, lmt);

    date = squid_curtime;

    content_length = clen;

    expires = expiresTime;

    last_modified = lmt;
}

void
HttpReply::redirect(Http::StatusCode status, const char *loc)
{
    HttpHeader *hdr;
    sline.set(Http::ProtocolVersion(1,1), status, NULL);
    hdr = &header;
    hdr->putStr(HDR_SERVER, APP_FULLNAME);
    hdr->putTime(HDR_DATE, squid_curtime);
    hdr->putInt64(HDR_CONTENT_LENGTH, 0);
    hdr->putStr(HDR_LOCATION, loc);
    date = squid_curtime;
    content_length = 0;
}

/* compare the validators of two replies.
 * 1 = they match
 * 0 = they do not match
 */
int
HttpReply::validatorsMatch(HttpReply const * otherRep) const
{
    String one,two;
    assert (otherRep);
    /* Numbers first - easiest to check */
    /* Content-Length */
    /* TODO: remove -1 bypass */

    if (content_length != otherRep->content_length
            && content_length > -1 &&
            otherRep->content_length > -1)
        return 0;

    /* ETag */
    one = header.getStrOrList(HDR_ETAG);

    two = otherRep->header.getStrOrList(HDR_ETAG);

    if (one.size()==0 || two.size()==0 || one.caseCmp(two)!=0 ) {
        one.clean();
        two.clean();
        return 0;
    }

    if (last_modified != otherRep->last_modified)
        return 0;

    /* MD5 */
    one = header.getStrOrList(HDR_CONTENT_MD5);

    two = otherRep->header.getStrOrList(HDR_CONTENT_MD5);

    if (one.size()==0 || two.size()==0 || one.caseCmp(two)!=0 ) {
        one.clean();
        two.clean();
        return 0;
    }

    return 1;
}

bool
HttpReply::updateOnNotModified(HttpReply const * freshRep)
{
    assert(freshRep);

    /* update raw headers */
    if (!header.update(&freshRep->header))
        return false;

    /* clean cache */
    hdrCacheClean();

    header.compact();
    /* init cache */
    hdrCacheInit();

    return true;
}

/* internal routines */

time_t
HttpReply::hdrExpirationTime()
{
    /* The s-maxage and max-age directive takes priority over Expires */

    if (cache_control) {
        if (date >= 0) {
            if (cache_control->hasSMaxAge())
                return date + cache_control->sMaxAge();

            if (cache_control->hasMaxAge())
                return date + cache_control->maxAge();
        } else {
            /*
             * Conservatively handle the case when we have a max-age
             * header, but no Date for reference?
             */

            if (cache_control->hasSMaxAge())
                return squid_curtime;

            if (cache_control->hasMaxAge())
                return squid_curtime;
        }
    }

    if (Config.onoff.vary_ignore_expire &&
            header.has(HDR_VARY)) {
        const time_t d = header.getTime(HDR_DATE);
        const time_t e = header.getTime(HDR_EXPIRES);

        if (d == e)
            return -1;
    }

    if (header.has(HDR_EXPIRES)) {
        const time_t e = header.getTime(HDR_EXPIRES);
        /*
         * HTTP/1.0 says that robust implementations should consider
         * bad or malformed Expires header as equivalent to "expires
         * immediately."
         */
        return e < 0 ? squid_curtime : e;
    }

    return -1;
}

/* sync this routine when you update HttpReply struct */
void
HttpReply::hdrCacheInit()
{
    HttpMsg::hdrCacheInit();

    http_ver = sline.version;
    content_length = header.getInt64(HDR_CONTENT_LENGTH);
    date = header.getTime(HDR_DATE);
    last_modified = header.getTime(HDR_LAST_MODIFIED);
    surrogate_control = header.getSc();
    content_range = (sline.status() == Http::scPartialContent) ?
                    header.getContRange() : nullptr;
    keep_alive = persistent() ? 1 : 0;
    const char *str = header.getStr(HDR_CONTENT_TYPE);

    if (str)
        content_type.limitInit(str, strcspn(str, ";\t "));
    else
        content_type = String();

    /* be sure to set expires after date and cache-control */
    expires = hdrExpirationTime();
}

const HttpHdrContRange *
HttpReply::contentRange() const
{
    assert(!content_range || sline.status() == Http::scPartialContent);
    return content_range;
}

/* sync this routine when you update HttpReply struct */
void
HttpReply::hdrCacheClean()
{
    content_type.clean();

    if (cache_control) {
        delete cache_control;
        cache_control = NULL;
    }

    if (surrogate_control) {
        delete surrogate_control;
        surrogate_control = NULL;
    }

    if (content_range) {
        httpHdrContRangeDestroy(content_range);
        content_range = NULL;
    }
}

/*
 * Returns the body size of a HTTP response
 */
int64_t
HttpReply::bodySize(const HttpRequestMethod& method) const
{
    if (sline.version.major < 1)
        return -1;
    else if (method.id() == Http::METHOD_HEAD)
        return 0;
    else if (sline.status() == Http::scOkay)
        (void) 0;       /* common case, continue */
    else if (sline.status() == Http::scNoContent)
        return 0;
    else if (sline.status() == Http::scNotModified)
        return 0;
    else if (sline.status() < Http::scOkay)
        return 0;

    return content_length;
}

/**
 * Checks the first line of an HTTP Reply is valid.
 * currently only checks "HTTP/" exists.
 *
 * NP: not all error cases are detected yet. Some are left for detection later in parse.
 */
bool
HttpReply::sanityCheckStartLine(MemBuf *buf, const size_t hdr_len, Http::StatusCode *error)
{
    // hack warning: using psize instead of size here due to type mismatches with MemBuf.

    // content is long enough to possibly hold a reply
    // 4 being magic size of a 3-digit number plus space delimiter
    if ( buf->contentSize() < (protoPrefix.psize() + 4) ) {
        if (hdr_len > 0) {
            debugs(58, 3, HERE << "Too small reply header (" << hdr_len << " bytes)");
            *error = Http::scInvalidHeader;
        }
        return false;
    }

    int pos;
    // catch missing or mismatched protocol identifier
    // allow special-case for ICY protocol (non-HTTP identifier) in response to faked HTTP request.
    if (strncmp(buf->content(), "ICY", 3) == 0) {
        protoPrefix = "ICY";
        pos = protoPrefix.psize();
    } else {

        if (protoPrefix.cmp(buf->content(), protoPrefix.size()) != 0) {
            debugs(58, 3, "HttpReply::sanityCheckStartLine: missing protocol prefix (" << protoPrefix << ") in '" << buf->content() << "'");
            *error = Http::scInvalidHeader;
            return false;
        }

        // catch missing or negative status value (negative '-' is not a digit)
        pos = protoPrefix.psize();

        // skip arbitrary number of digits and a dot in the verion portion
        while ( pos <= buf->contentSize() && (*(buf->content()+pos) == '.' || xisdigit(*(buf->content()+pos)) ) ) ++pos;

        // catch missing version info
        if (pos == protoPrefix.psize()) {
            debugs(58, 3, "HttpReply::sanityCheckStartLine: missing protocol version numbers (ie. " << protoPrefix << "/1.0) in '" << buf->content() << "'");
            *error = Http::scInvalidHeader;
            return false;
        }
    }

    // skip arbitrary number of spaces...
    while (pos <= buf->contentSize() && (char)*(buf->content()+pos) == ' ') ++pos;

    if (pos < buf->contentSize() && !xisdigit(*(buf->content()+pos))) {
        debugs(58, 3, "HttpReply::sanityCheckStartLine: missing or invalid status number in '" << buf->content() << "'");
        *error = Http::scInvalidHeader;
        return false;
    }

    return true;
}

bool
HttpReply::parseFirstLine(const char *blk_start, const char *blk_end)
{
    return sline.parse(protoPrefix, blk_start, blk_end);
}

/* handy: resets and returns -1 */
int
HttpReply::httpMsgParseError()
{
    int result(HttpMsg::httpMsgParseError());
    /* indicate an error in the status line */
    sline.set(Http::ProtocolVersion(1,1), Http::scInvalidHeader);
    return result;
}

/*
 * Indicate whether or not we would usually expect an entity-body
 * along with this response
 */
bool
HttpReply::expectingBody(const HttpRequestMethod& req_method, int64_t& theSize) const
{
    bool expectBody = true;

    if (req_method == Http::METHOD_HEAD)
        expectBody = false;
    else if (sline.status() == Http::scNoContent)
        expectBody = false;
    else if (sline.status() == Http::scNotModified)
        expectBody = false;
    else if (sline.status() < Http::scOkay)
        expectBody = false;
    else
        expectBody = true;

    if (expectBody) {
        if (header.chunked())
            theSize = -1;
        else if (content_length >= 0)
            theSize = content_length;
        else
            theSize = -1;
    }

    return expectBody;
}

bool
HttpReply::receivedBodyTooLarge(HttpRequest& request, int64_t receivedSize)
{
    calcMaxBodySize(request);
    debugs(58, 3, HERE << receivedSize << " >? " << bodySizeMax);
    return bodySizeMax >= 0 && receivedSize > bodySizeMax;
}

bool
HttpReply::expectedBodyTooLarge(HttpRequest& request)
{
    calcMaxBodySize(request);
    debugs(58, 7, HERE << "bodySizeMax=" << bodySizeMax);

    if (bodySizeMax < 0) // no body size limit
        return false;

    int64_t expectedSize = -1;
    if (!expectingBody(request.method, expectedSize))
        return false;

    debugs(58, 6, HERE << expectedSize << " >? " << bodySizeMax);

    if (expectedSize < 0) // expecting body of an unknown length
        return false;

    return expectedSize > bodySizeMax;
}

void
HttpReply::calcMaxBodySize(HttpRequest& request) const
{
    // hack: -2 is used as "we have not calculated max body size yet" state
    if (bodySizeMax != -2) // already tried
        return;
    bodySizeMax = -1;

    // short-circuit ACL testing if there are none configured
    if (!Config.ReplyBodySize)
        return;

    ACLFilledChecklist ch(NULL, &request, NULL);
    // XXX: cont-cast becomes irrelevant when checklist is HttpReply::Pointer
    ch.reply = const_cast<HttpReply *>(this);
    HTTPMSGLOCK(ch.reply);
    for (AclSizeLimit *l = Config.ReplyBodySize; l; l = l -> next) {
        /* if there is no ACL list or if the ACLs listed match use this size value */
        if (!l->aclList || ch.fastCheck(l->aclList) == ACCESS_ALLOWED) {
            debugs(58, 4, HERE << "bodySizeMax=" << bodySizeMax);
            bodySizeMax = l->size; // may be -1
            break;
        }
    }
}

// XXX: check that this is sufficient for eCAP cloning
HttpReply *
HttpReply::clone() const
{
    HttpReply *rep = new HttpReply();
    rep->sline = sline; // used in hdrCacheInit() call below
    rep->header.append(&header);
    rep->hdrCacheInit();
    rep->hdr_sz = hdr_sz;
    rep->http_ver = http_ver;
    rep->pstate = pstate;
    rep->body_pipe = body_pipe;

    // keep_alive is handled in hdrCacheInit()
    return rep;
}

bool HttpReply::inheritProperties(const HttpMsg *aMsg)
{
    const HttpReply *aRep = dynamic_cast<const HttpReply*>(aMsg);
    if (!aRep)
        return false;
    keep_alive = aRep->keep_alive;
    return true;
}

void HttpReply::removeStaleWarnings()
{
    String warning;
    if (header.getList(HDR_WARNING, &warning)) {
        const String newWarning = removeStaleWarningValues(warning);
        if (warning.size() && warning.size() == newWarning.size())
            return; // some warnings are there and none changed
        header.delById(HDR_WARNING);
        if (newWarning.size()) { // some warnings left
            HttpHeaderEntry *const e =
                new HttpHeaderEntry(HDR_WARNING, NULL, newWarning.termedBuf());
            header.addEntry(e);
        }
    }
}

/**
 * Remove warning-values with warn-date different from Date value from
 * a single header entry. Returns a string with all valid warning-values.
 */
String HttpReply::removeStaleWarningValues(const String &value)
{
    String newValue;
    const char *item = 0;
    int len = 0;
    const char *pos = 0;
    while (strListGetItem(&value, ',', &item, &len, &pos)) {
        bool keep = true;
        // Does warning-value have warn-date (which contains quoted date)?
        // We scan backwards, looking for two quoted strings.
        // warning-value = warn-code SP warn-agent SP warn-text [SP warn-date]
        const char *p = item + len - 1;

        while (p >= item && xisspace(*p)) --p; // skip whitespace

        // warning-value MUST end with quote
        if (p >= item && *p == '"') {
            const char *const warnDateEnd = p;
            --p;
            while (p >= item && *p != '"') --p; // find the next quote

            const char *warnDateBeg = p + 1;
            --p;
            while (p >= item && xisspace(*p)) --p; // skip whitespace

            if (p >= item && *p == '"' && warnDateBeg - p > 2) {
                // found warn-text
                String warnDate;
                warnDate.append(warnDateBeg, warnDateEnd - warnDateBeg);
                const time_t time = parse_rfc1123(warnDate.termedBuf());
                keep = (time > 0 && time == date); // keep valid and matching date
            }
        }

        if (keep) {
            if (newValue.size())
                newValue.append(", ");
            newValue.append(item, len);
        }
    }

    return newValue;
}

bool
HttpReply::olderThan(const HttpReply *them) const
{
    if (!them || !them->date || !date)
        return false;
    return date < them->date;
}

