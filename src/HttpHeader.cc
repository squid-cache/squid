/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 55    HTTP Header */

#include "squid.h"
#include "base64.h"
#include "globals.h"
#include "HttpHdrCc.h"
#include "HttpHdrContRange.h"
#include "HttpHdrSc.h"
#include "HttpHeader.h"
#include "HttpHeaderFieldInfo.h"
#include "HttpHeaderStat.h"
#include "HttpHeaderTools.h"
#include "MemBuf.h"
#include "mgr/Registration.h"
#include "profiler/Profiler.h"
#include "rfc1123.h"
#include "SquidConfig.h"
#include "SquidString.h"
#include "StatHist.h"
#include "Store.h"
#include "StrList.h"
#include "TimeOrTag.h"

#include <algorithm>

/* XXX: the whole set of API managing the entries vector should be rethought
 *      after the parse4r-ng effort is complete.
 */

/*
 * On naming conventions:
 *
 * HTTP/1.1 defines message-header as
 *
 * message-header = field-name ":" [ field-value ] CRLF
 * field-name     = token
 * field-value    = *( field-content | LWS )
 *
 * HTTP/1.1 does not give a name name a group of all message-headers in a message.
 * Squid 1.1 seems to refer to that group _plus_ start-line as "headers".
 *
 * HttpHeader is an object that represents all message-headers in a message.
 * HttpHeader does not manage start-line.
 *
 * HttpHeader is implemented as a collection of header "entries".
 * An entry is a (field_id, field_name, field_value) triplet.
 */

/*
 * local constants and vars
 */

/*
 * A table with major attributes for every known field.
 * We calculate name lengths and reorganize this array on start up.
 * After reorganization, field id can be used as an index to the table.
 */
static const HttpHeaderFieldAttrs HeadersAttrs[] = {
    {"Accept", HDR_ACCEPT, ftStr},

    {"Accept-Charset", HDR_ACCEPT_CHARSET, ftStr},
    {"Accept-Encoding", HDR_ACCEPT_ENCODING, ftStr},
    {"Accept-Language", HDR_ACCEPT_LANGUAGE, ftStr},
    {"Accept-Ranges", HDR_ACCEPT_RANGES, ftStr},
    {"Age", HDR_AGE, ftInt},
    {"Allow", HDR_ALLOW, ftStr},
    {"Alternate-Protocol", HDR_ALTERNATE_PROTOCOL, ftStr},
    {"Authorization", HDR_AUTHORIZATION, ftStr},    /* for now */
    {"Cache-Control", HDR_CACHE_CONTROL, ftPCc},
    {"Connection", HDR_CONNECTION, ftStr},
    {"Content-Base", HDR_CONTENT_BASE, ftStr},
    {"Content-Disposition", HDR_CONTENT_DISPOSITION, ftStr},  /* for now */
    {"Content-Encoding", HDR_CONTENT_ENCODING, ftStr},
    {"Content-Language", HDR_CONTENT_LANGUAGE, ftStr},
    {"Content-Length", HDR_CONTENT_LENGTH, ftInt64},
    {"Content-Location", HDR_CONTENT_LOCATION, ftStr},
    {"Content-MD5", HDR_CONTENT_MD5, ftStr},    /* for now */
    {"Content-Range", HDR_CONTENT_RANGE, ftPContRange},
    {"Content-Type", HDR_CONTENT_TYPE, ftStr},
    {"Cookie", HDR_COOKIE, ftStr},
    {"Cookie2", HDR_COOKIE2, ftStr},
    {"Date", HDR_DATE, ftDate_1123},
    {"ETag", HDR_ETAG, ftETag},
    {"Expect", HDR_EXPECT, ftStr},
    {"Expires", HDR_EXPIRES, ftDate_1123},
    {"Forwarded", HDR_FORWARDED, ftStr},
    {"From", HDR_FROM, ftStr},
    {"Host", HDR_HOST, ftStr},
    {"HTTP2-Settings", HDR_HTTP2_SETTINGS, ftStr}, /* for now */
    {"If-Match", HDR_IF_MATCH, ftStr},  /* for now */
    {"If-Modified-Since", HDR_IF_MODIFIED_SINCE, ftDate_1123},
    {"If-None-Match", HDR_IF_NONE_MATCH, ftStr},    /* for now */
    {"If-Range", HDR_IF_RANGE, ftDate_1123_or_ETag},
    {"If-Unmodified-Since", HDR_IF_UNMODIFIED_SINCE, ftDate_1123},
    {"Keep-Alive", HDR_KEEP_ALIVE, ftStr},
    {"Key", HDR_KEY, ftStr},
    {"Last-Modified", HDR_LAST_MODIFIED, ftDate_1123},
    {"Link", HDR_LINK, ftStr},
    {"Location", HDR_LOCATION, ftStr},
    {"Max-Forwards", HDR_MAX_FORWARDS, ftInt64},
    {"Mime-Version", HDR_MIME_VERSION, ftStr},  /* for now */
    {"Negotiate", HDR_NEGOTIATE, ftStr},
    {"Origin", HDR_ORIGIN, ftStr},
    {"Pragma", HDR_PRAGMA, ftStr},
    {"Proxy-Authenticate", HDR_PROXY_AUTHENTICATE, ftStr},
    {"Proxy-Authentication-Info", HDR_PROXY_AUTHENTICATION_INFO, ftStr},
    {"Proxy-Authorization", HDR_PROXY_AUTHORIZATION, ftStr},
    {"Proxy-Connection", HDR_PROXY_CONNECTION, ftStr},
    {"Proxy-support", HDR_PROXY_SUPPORT, ftStr},
    {"Public", HDR_PUBLIC, ftStr},
    {"Range", HDR_RANGE, ftPRange},
    {"Referer", HDR_REFERER, ftStr},
    {"Request-Range", HDR_REQUEST_RANGE, ftPRange}, /* usually matches HDR_RANGE */
    {"Retry-After", HDR_RETRY_AFTER, ftStr},    /* for now (ftDate_1123 or ftInt!) */
    {"Server", HDR_SERVER, ftStr},
    {"Set-Cookie", HDR_SET_COOKIE, ftStr},
    {"Set-Cookie2", HDR_SET_COOKIE2, ftStr},
    {"TE", HDR_TE, ftStr},
    {"Title", HDR_TITLE, ftStr},
    {"Trailer", HDR_TRAILER, ftStr},
    {"Transfer-Encoding", HDR_TRANSFER_ENCODING, ftStr},
    {"Translate", HDR_TRANSLATE, ftStr},    /* for now. may need to crop */
    {"Unless-Modified-Since", HDR_UNLESS_MODIFIED_SINCE, ftStr},  /* for now ignore. may need to crop */
    {"Upgrade", HDR_UPGRADE, ftStr},    /* for now */
    {"User-Agent", HDR_USER_AGENT, ftStr},
    {"Vary", HDR_VARY, ftStr},  /* for now */
    {"Via", HDR_VIA, ftStr},    /* for now */
    {"Warning", HDR_WARNING, ftStr},    /* for now */
    {"WWW-Authenticate", HDR_WWW_AUTHENTICATE, ftStr},
    {"Authentication-Info", HDR_AUTHENTICATION_INFO, ftStr},
    {"X-Cache", HDR_X_CACHE, ftStr},
    {"X-Cache-Lookup", HDR_X_CACHE_LOOKUP, ftStr},
    {"X-Forwarded-For", HDR_X_FORWARDED_FOR, ftStr},
    {"X-Request-URI", HDR_X_REQUEST_URI, ftStr},
    {"X-Squid-Error", HDR_X_SQUID_ERROR, ftStr},
#if X_ACCELERATOR_VARY
    {"X-Accelerator-Vary", HDR_X_ACCELERATOR_VARY, ftStr},
#endif
#if USE_ADAPTATION
    {"X-Next-Services", HDR_X_NEXT_SERVICES, ftStr},
#endif
    {"Surrogate-Capability", HDR_SURROGATE_CAPABILITY, ftStr},
    {"Surrogate-Control", HDR_SURROGATE_CONTROL, ftPSc},
    {"Front-End-Https", HDR_FRONT_END_HTTPS, ftStr},
    {"FTP-Command", HDR_FTP_COMMAND, ftStr},
    {"FTP-Arguments", HDR_FTP_ARGUMENTS, ftStr},
    {"FTP-Pre", HDR_FTP_PRE, ftStr},
    {"FTP-Status", HDR_FTP_STATUS, ftInt},
    {"FTP-Reason", HDR_FTP_REASON, ftStr},
    {"Other:", HDR_OTHER, ftStr}    /* ':' will not allow matches */
};

static HttpHeaderFieldInfo *Headers = NULL;

http_hdr_type &operator++ (http_hdr_type &aHeader)
{
    int tmp = (int)aHeader;
    aHeader = (http_hdr_type)(++tmp);
    return aHeader;
}

/*
 * headers with field values defined as #(values) in HTTP/1.1
 * Headers that are currently not recognized, are commented out.
 */
static HttpHeaderMask ListHeadersMask;  /* set run-time using  ListHeadersArr */
static http_hdr_type ListHeadersArr[] = {
    HDR_ACCEPT,
    HDR_ACCEPT_CHARSET,
    HDR_ACCEPT_ENCODING,
    HDR_ACCEPT_LANGUAGE,
    HDR_ACCEPT_RANGES,
    HDR_ALLOW,
    HDR_CACHE_CONTROL,
    HDR_CONTENT_ENCODING,
    HDR_CONTENT_LANGUAGE,
    HDR_CONNECTION,
    HDR_EXPECT,
    HDR_IF_MATCH,
    HDR_IF_NONE_MATCH,
    HDR_KEY,
    HDR_LINK,
    HDR_PRAGMA,
    HDR_PROXY_CONNECTION,
    HDR_PROXY_SUPPORT,
    HDR_TRANSFER_ENCODING,
    HDR_UPGRADE,
    HDR_VARY,
    HDR_VIA,
    HDR_WARNING,
    HDR_WWW_AUTHENTICATE,
    HDR_AUTHENTICATION_INFO,
    HDR_PROXY_AUTHENTICATION_INFO,
    /* HDR_TE, HDR_TRAILER */
#if X_ACCELERATOR_VARY
    HDR_X_ACCELERATOR_VARY,
#endif
#if USE_ADAPTATION
    HDR_X_NEXT_SERVICES,
#endif
    HDR_SURROGATE_CAPABILITY,
    HDR_SURROGATE_CONTROL,
    HDR_FORWARDED,
    HDR_X_FORWARDED_FOR
};

/* general-headers */
static http_hdr_type GeneralHeadersArr[] = {
    HDR_CACHE_CONTROL,
    HDR_CONNECTION,
    HDR_DATE,
    HDR_FORWARDED,
    HDR_X_FORWARDED_FOR,
    HDR_MIME_VERSION,
    HDR_PRAGMA,
    HDR_PROXY_CONNECTION,
    HDR_TRANSFER_ENCODING,
    HDR_UPGRADE,
    /* HDR_TRAILER, */
    HDR_VIA,
};

/* entity-headers */
static http_hdr_type EntityHeadersArr[] = {
    HDR_ALLOW,
    HDR_CONTENT_BASE,
    HDR_CONTENT_ENCODING,
    HDR_CONTENT_LANGUAGE,
    HDR_CONTENT_LENGTH,
    HDR_CONTENT_LOCATION,
    HDR_CONTENT_MD5,
    HDR_CONTENT_RANGE,
    HDR_CONTENT_TYPE,
    HDR_ETAG,
    HDR_EXPIRES,
    HDR_LAST_MODIFIED,
    HDR_LINK,
    HDR_OTHER
};

/* request-only headers */
static HttpHeaderMask RequestHeadersMask;   /* set run-time using RequestHeaders */
static http_hdr_type RequestHeadersArr[] = {
    HDR_ACCEPT,
    HDR_ACCEPT_CHARSET,
    HDR_ACCEPT_ENCODING,
    HDR_ACCEPT_LANGUAGE,
    HDR_AUTHORIZATION,
    HDR_EXPECT,
    HDR_FROM,
    HDR_HOST,
    HDR_HTTP2_SETTINGS,
    HDR_IF_MATCH,
    HDR_IF_MODIFIED_SINCE,
    HDR_IF_NONE_MATCH,
    HDR_IF_RANGE,
    HDR_IF_UNMODIFIED_SINCE,
    HDR_MAX_FORWARDS,
    HDR_ORIGIN,
    HDR_PROXY_AUTHORIZATION,
    HDR_RANGE,
    HDR_REFERER,
    HDR_REQUEST_RANGE,
    HDR_TE,
    HDR_USER_AGENT,
    HDR_SURROGATE_CAPABILITY
};

/* reply-only headers */
static HttpHeaderMask ReplyHeadersMask;     /* set run-time using ReplyHeaders */
static http_hdr_type ReplyHeadersArr[] = {
    HDR_ACCEPT_ENCODING,
    HDR_ACCEPT_RANGES,
    HDR_AGE,
    HDR_KEY,
    HDR_LOCATION,
    HDR_PROXY_AUTHENTICATE,
    HDR_PUBLIC,
    HDR_RETRY_AFTER,
    HDR_SERVER,
    HDR_SET_COOKIE,
    HDR_SET_COOKIE2,
    HDR_VARY,
    HDR_WARNING,
    HDR_WWW_AUTHENTICATE,
    HDR_X_CACHE,
    HDR_X_CACHE_LOOKUP,
    HDR_X_REQUEST_URI,
#if X_ACCELERATOR_VARY
    HDR_X_ACCELERATOR_VARY,
#endif
#if USE_ADAPTATION
    HDR_X_NEXT_SERVICES,
#endif
    HDR_X_SQUID_ERROR,
    HDR_SURROGATE_CONTROL
};

/* hop-by-hop headers */
static HttpHeaderMask HopByHopHeadersMask;
static http_hdr_type HopByHopHeadersArr[] = {
    HDR_ALTERNATE_PROTOCOL,
    HDR_CONNECTION,
    HDR_HTTP2_SETTINGS,
    HDR_KEEP_ALIVE,
    /*HDR_PROXY_AUTHENTICATE, // removal handled specially for peer login */
    HDR_PROXY_AUTHORIZATION,
    HDR_TE,
    HDR_TRAILER,
    HDR_TRANSFER_ENCODING,
    HDR_UPGRADE,
    HDR_PROXY_CONNECTION
};

/* header accounting */
static HttpHeaderStat HttpHeaderStats[] = {
    {"all"},
#if USE_HTCP
    {"HTCP reply"},
#endif
    {"request"},
    {"reply"}
};
static int HttpHeaderStatCount = countof(HttpHeaderStats);

static int HeaderEntryParsedCount = 0;

/*
 * forward declarations and local routines
 */

class StoreEntry;
#define assert_eid(id) assert((id) >= 0 && (id) < HDR_ENUM_END)

static void httpHeaderNoteParsedEntry(http_hdr_type id, String const &value, int error);

static void httpHeaderStatInit(HttpHeaderStat * hs, const char *label);
static void httpHeaderStatDump(const HttpHeaderStat * hs, StoreEntry * e);

/** store report about current header usage and other stats */
static void httpHeaderStoreReport(StoreEntry * e);

/*
 * Module initialization routines
 */

static void
httpHeaderRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("http_headers",
                        "HTTP Header Statistics",
                        httpHeaderStoreReport, 0, 1);
}

void
httpHeaderInitModule(void)
{
    int i;
    /* check that we have enough space for masks */
    assert(8 * sizeof(HttpHeaderMask) >= HDR_ENUM_END);
    /* all headers must be described */
    assert(countof(HeadersAttrs) == HDR_ENUM_END);

    if (!Headers)
        Headers = httpHeaderBuildFieldsInfo(HeadersAttrs, HDR_ENUM_END);

    /* create masks */
    httpHeaderMaskInit(&ListHeadersMask, 0);
    httpHeaderCalcMask(&ListHeadersMask, ListHeadersArr, countof(ListHeadersArr));

    httpHeaderMaskInit(&ReplyHeadersMask, 0);
    httpHeaderCalcMask(&ReplyHeadersMask, ReplyHeadersArr, countof(ReplyHeadersArr));
    httpHeaderCalcMask(&ReplyHeadersMask, GeneralHeadersArr, countof(GeneralHeadersArr));
    httpHeaderCalcMask(&ReplyHeadersMask, EntityHeadersArr, countof(EntityHeadersArr));

    httpHeaderMaskInit(&RequestHeadersMask, 0);
    httpHeaderCalcMask(&RequestHeadersMask, RequestHeadersArr, countof(RequestHeadersArr));
    httpHeaderCalcMask(&RequestHeadersMask, GeneralHeadersArr, countof(GeneralHeadersArr));
    httpHeaderCalcMask(&RequestHeadersMask, EntityHeadersArr, countof(EntityHeadersArr));

    httpHeaderMaskInit(&HopByHopHeadersMask, 0);
    httpHeaderCalcMask(&HopByHopHeadersMask, HopByHopHeadersArr, countof(HopByHopHeadersArr));

    /* init header stats */
    assert(HttpHeaderStatCount == hoReply + 1);
    for (i = 0; i < HttpHeaderStatCount; ++i)
        httpHeaderStatInit(HttpHeaderStats + i, HttpHeaderStats[i].label);

    HttpHeaderStats[hoRequest].owner_mask = &RequestHeadersMask;

    HttpHeaderStats[hoReply].owner_mask = &ReplyHeadersMask;

#if USE_HTCP
    HttpHeaderStats[hoHtcpReply].owner_mask = &ReplyHeadersMask;
#endif

    /* init dependent modules */
    httpHdrCcInitModule();
    httpHdrScInitModule();

    httpHeaderRegisterWithCacheManager();
}

void
httpHeaderCleanModule(void)
{
    httpHeaderDestroyFieldsInfo(Headers, HDR_ENUM_END);
    Headers = NULL;
    httpHdrCcCleanModule();
    httpHdrScCleanModule();
}

static void
httpHeaderStatInit(HttpHeaderStat * hs, const char *label)
{
    assert(hs);
    assert(label);
    memset(hs, 0, sizeof(HttpHeaderStat));
    hs->label = label;
    hs->hdrUCountDistr.enumInit(32);    /* not a real enum */
    hs->fieldTypeDistr.enumInit(HDR_ENUM_END);
    hs->ccTypeDistr.enumInit(CC_ENUM_END);
    hs->scTypeDistr.enumInit(SC_ENUM_END);
}

/*
 * HttpHeader Implementation
 */

HttpHeader::HttpHeader() : owner (hoNone), len (0), conflictingContentLength_(false)
{
    httpHeaderMaskInit(&mask, 0);
}

HttpHeader::HttpHeader(const http_hdr_owner_type anOwner): owner(anOwner), len(0), conflictingContentLength_(false)
{
    assert(anOwner > hoNone && anOwner < hoEnd);
    debugs(55, 7, "init-ing hdr: " << this << " owner: " << owner);
    httpHeaderMaskInit(&mask, 0);
}

HttpHeader::HttpHeader(const HttpHeader &other): owner(other.owner), len(other.len), conflictingContentLength_(false)
{
    httpHeaderMaskInit(&mask, 0);
    update(&other); // will update the mask as well
}

HttpHeader::~HttpHeader()
{
    clean();
}

HttpHeader &
HttpHeader::operator =(const HttpHeader &other)
{
    if (this != &other) {
        // we do not really care, but the caller probably does
        assert(owner == other.owner);
        clean();
        update(&other); // will update the mask as well
        len = other.len;
        conflictingContentLength_ = other.conflictingContentLength_;
    }
    return *this;
}

void
HttpHeader::clean()
{

    assert(owner > hoNone && owner < hoEnd);
    debugs(55, 7, "cleaning hdr: " << this << " owner: " << owner);

    PROF_start(HttpHeaderClean);

    if (owner <= hoReply) {
        /*
         * An unfortunate bug.  The entries array is initialized
         * such that count is set to zero.  httpHeaderClean() seems to
         * be called both when 'hdr' is created, and destroyed.  Thus,
         * we accumulate a large number of zero counts for 'hdr' before
         * it is ever used.  Can't think of a good way to fix it, except
         * adding a state variable that indicates whether or not 'hdr'
         * has been used.  As a hack, just never count zero-sized header
         * arrays.
         */
        if (!entries.empty())
            HttpHeaderStats[owner].hdrUCountDistr.count(entries.size());

        ++ HttpHeaderStats[owner].destroyedCount;

        HttpHeaderStats[owner].busyDestroyedCount += entries.size() > 0;
    } // if (owner <= hoReply)

    for (std::vector<HttpHeaderEntry *>::iterator i = entries.begin(); i != entries.end(); ++i) {
        HttpHeaderEntry *e = *i;
        if (e == NULL)
            continue;
        if (e->id < 0 || e->id >= HDR_ENUM_END) {
            debugs(55, DBG_CRITICAL, "BUG: invalid entry (" << e->id << "). Ignored.");
        } else {
            if (owner <= hoReply)
                HttpHeaderStats[owner].fieldTypeDistr.count(e->id);
            delete e;
        }
    }

    entries.clear();
    httpHeaderMaskInit(&mask, 0);
    len = 0;
    conflictingContentLength_ = false;
    PROF_stop(HttpHeaderClean);
}

/* append entries (also see httpHeaderUpdate) */
void
HttpHeader::append(const HttpHeader * src)
{
    const HttpHeaderEntry *e;
    HttpHeaderPos pos = HttpHeaderInitPos;
    assert(src);
    assert(src != this);
    debugs(55, 7, "appending hdr: " << this << " += " << src);

    while ((e = src->getEntry(&pos))) {
        addEntry(e->clone());
    }
}

/// check whether the fresh header has any new/changed updatable fields
bool
HttpHeader::needUpdate(HttpHeader const *fresh) const
{
    for (unsigned int i = 0; i < fresh->entries.size(); ++i) {
        const HttpHeaderEntry *e = fresh->entries[i];
        if (!e || skipUpdateHeader(e->id))
            continue;
        String value;
        const char *name = e->name.termedBuf();
        if (!getByNameIfPresent(name, value) ||
                (value != fresh->getByName(name)))
            return true;
    }
    return false;
}

/* use fresh entries to replace old ones */
void
httpHeaderUpdate(HttpHeader * old, const HttpHeader * fresh, const HttpHeaderMask * denied_mask)
{
    assert (old);
    old->update(fresh);
}

void
HttpHeader::updateWarnings()
{
    int count = 0;
    HttpHeaderPos pos = HttpHeaderInitPos;

    // RFC 7234, section 4.3.4: delete 1xx warnings and retain 2xx warnings
    while (HttpHeaderEntry *e = getEntry(&pos)) {
        if (e->id == HDR_WARNING && (e->getInt()/100 == 1) )
            delAt(pos, count);
    }
}

bool
HttpHeader::skipUpdateHeader(const http_hdr_type id) const
{
    // RFC 7234, section 4.3.4: use fields other from Warning for update
    return id == HDR_WARNING;
}

bool
HttpHeader::update(HttpHeader const *fresh)
{
    assert(fresh);
    assert(this != fresh);

    // Optimization: Finding whether a header field changed is expensive
    // and probably not worth it except for collapsed revalidation needs.
    if (Config.onoff.collapsed_forwarding && !needUpdate(fresh))
        return false;

    updateWarnings();

    const HttpHeaderEntry *e;
    HttpHeaderPos pos = HttpHeaderInitPos;

    while ((e = fresh->getEntry(&pos))) {
        /* deny bad guys (ok to check for HDR_OTHER) here */

        if (skipUpdateHeader(e->id))
            continue;

        if (e->id != HDR_OTHER)
            delById(e->id);
        else
            delByName(e->name.termedBuf());
    }

    pos = HttpHeaderInitPos;
    while ((e = fresh->getEntry(&pos))) {
        /* deny bad guys (ok to check for HDR_OTHER) here */

        if (skipUpdateHeader(e->id))
            continue;

        debugs(55, 7, "Updating header '" << HeadersAttrs[e->id].name << "' in cached entry");

        addEntry(e->clone());
    }
    return true;
}

/* just handy in parsing: resets and returns false */
int
HttpHeader::reset()
{
    clean();
    return 0;
}

int
HttpHeader::parse(const char *header_start, const char *header_end)
{
    const char *field_ptr = header_start;
    HttpHeaderEntry *e, *e2;
    int warnOnError = (Config.onoff.relaxed_header_parser <= 0 ? DBG_IMPORTANT : 2);

    PROF_start(HttpHeaderParse);

    assert(header_start && header_end);
    debugs(55, 7, "parsing hdr: (" << this << ")" << std::endl << getStringPrefix(header_start, header_end));
    ++ HttpHeaderStats[owner].parsedCount;

    char *nulpos;
    if ((nulpos = (char*)memchr(header_start, '\0', header_end - header_start))) {
        debugs(55, DBG_IMPORTANT, "WARNING: HTTP header contains NULL characters {" <<
               getStringPrefix(header_start, nulpos) << "}\nNULL\n{" << getStringPrefix(nulpos+1, header_end));
        PROF_stop(HttpHeaderParse);
        return reset();
    }

    /* common format headers are "<name>:[ws]<value>" lines delimited by <CRLF>.
     * continuation lines start with a (single) space or tab */
    while (field_ptr < header_end) {
        const char *field_start = field_ptr;
        const char *field_end;

        do {
            const char *this_line = field_ptr;
            field_ptr = (const char *)memchr(field_ptr, '\n', header_end - field_ptr);

            if (!field_ptr) {
                // missing <LF>
                PROF_stop(HttpHeaderParse);
                return reset();
            }

            field_end = field_ptr;

            ++field_ptr;    /* Move to next line */

            if (field_end > this_line && field_end[-1] == '\r') {
                --field_end;    /* Ignore CR LF */

                if (owner == hoRequest && field_end > this_line) {
                    bool cr_only = true;
                    for (const char *p = this_line; p < field_end && cr_only; ++p) {
                        if (*p != '\r')
                            cr_only = false;
                    }
                    if (cr_only) {
                        debugs(55, DBG_IMPORTANT, "SECURITY WARNING: Rejecting HTTP request with a CR+ "
                               "header field to prevent request smuggling attacks: {" <<
                               getStringPrefix(header_start, header_end) << "}");
                        PROF_stop(HttpHeaderParse);
                        return reset();
                    }
                }
            }

            /* Barf on stray CR characters */
            if (memchr(this_line, '\r', field_end - this_line)) {
                debugs(55, warnOnError, "WARNING: suspicious CR characters in HTTP header {" <<
                       getStringPrefix(field_start, field_end) << "}");

                if (Config.onoff.relaxed_header_parser) {
                    char *p = (char *) this_line;   /* XXX Warning! This destroys original header content and violates specifications somewhat */

                    while ((p = (char *)memchr(p, '\r', field_end - p)) != NULL) {
                        *p = ' ';
                        ++p;
                    }
                } else {
                    PROF_stop(HttpHeaderParse);
                    return reset();
                }
            }

            if (this_line + 1 == field_end && this_line > field_start) {
                debugs(55, warnOnError, "WARNING: Blank continuation line in HTTP header {" <<
                       getStringPrefix(header_start, header_end) << "}");
                PROF_stop(HttpHeaderParse);
                return reset();
            }
        } while (field_ptr < header_end && (*field_ptr == ' ' || *field_ptr == '\t'));

        if (field_start == field_end) {
            if (field_ptr < header_end) {
                debugs(55, warnOnError, "WARNING: unparseable HTTP header field near {" <<
                       getStringPrefix(field_start, header_end) << "}");
                PROF_stop(HttpHeaderParse);
                return reset();
            }

            break;      /* terminating blank line */
        }

        if ((e = HttpHeaderEntry::parse(field_start, field_end)) == NULL) {
            debugs(55, warnOnError, "WARNING: unparseable HTTP header field {" <<
                   getStringPrefix(field_start, field_end) << "}");
            debugs(55, warnOnError, " in {" << getStringPrefix(header_start, header_end) << "}");

            if (Config.onoff.relaxed_header_parser)
                continue;

            PROF_stop(HttpHeaderParse);
            return reset();
        }

        // XXX: RFC 7230 Section 3.3.3 item #4 requires sending a 502 error in
        // several cases that we do not yet cover. TODO: Rewrite to cover more.
        if (e->id == HDR_CONTENT_LENGTH && (e2 = findEntry(e->id)) != NULL) {
            if (e->value != e2->value) {
                int64_t l1, l2;
                debugs(55, warnOnError, "WARNING: found two conflicting content-length headers in {" <<
                       getStringPrefix(header_start, header_end) << "}");

                if (!Config.onoff.relaxed_header_parser) {
                    delete e;
                    PROF_stop(HttpHeaderParse);
                    return reset();
                }

                if (!httpHeaderParseOffset(e->value.termedBuf(), &l1)) {
                    debugs(55, DBG_IMPORTANT, "WARNING: Unparseable content-length '" << e->value << "'");
                    delete e;
                    continue;
                } else if (!httpHeaderParseOffset(e2->value.termedBuf(), &l2)) {
                    debugs(55, DBG_IMPORTANT, "WARNING: Unparseable content-length '" << e2->value << "'");
                    delById(e2->id);
                } else {
                    if (l1 != l2)
                        conflictingContentLength_ = true;
                    delete e;
                    continue;
                }
            } else {
                debugs(55, warnOnError, "NOTICE: found double content-length header");
                delete e;

                if (Config.onoff.relaxed_header_parser)
                    continue;

                PROF_stop(HttpHeaderParse);
                return reset();
            }
        }

        if (e->id == HDR_OTHER && stringHasWhitespace(e->name.termedBuf())) {
            debugs(55, warnOnError, "WARNING: found whitespace in HTTP header name {" <<
                   getStringPrefix(field_start, field_end) << "}");

            if (!Config.onoff.relaxed_header_parser) {
                delete e;
                PROF_stop(HttpHeaderParse);
                return reset();
            }
        }

        addEntry(e);
    }

    if (chunked()) {
        // RFC 2616 section 4.4: ignore Content-Length with Transfer-Encoding
        delById(HDR_CONTENT_LENGTH);
        // RFC 7230 section 3.3.3 #4: ignore Content-Length conflicts with Transfer-Encoding
        conflictingContentLength_ = false;
    } else if (conflictingContentLength_) {
        // ensure our callers do not see the conflicting Content-Length value
        delById(HDR_CONTENT_LENGTH);
    }

    PROF_stop(HttpHeaderParse);
    return 1;           /* even if no fields where found, it is a valid header */
}

/* packs all the entries using supplied packer */
void
HttpHeader::packInto(Packer * p, bool mask_sensitive_info) const
{
    HttpHeaderPos pos = HttpHeaderInitPos;
    const HttpHeaderEntry *e;
    assert(p);
    debugs(55, 7, this << " into " << p <<
           (mask_sensitive_info ? " while masking" : ""));
    /* pack all entries one by one */
    while ((e = getEntry(&pos))) {
        if (!mask_sensitive_info) {
            e->packInto(p);
            continue;
        }

        bool maskThisEntry = false;
        switch (e->id) {
        case HDR_AUTHORIZATION:
        case HDR_PROXY_AUTHORIZATION:
            maskThisEntry = true;
            break;

        case HDR_FTP_ARGUMENTS:
            if (const HttpHeaderEntry *cmd = findEntry(HDR_FTP_COMMAND))
                maskThisEntry = (cmd->value == "PASS");
            break;

        default:
            break;
        }
        if (maskThisEntry) {
            packerAppend(p, e->name.rawBuf(), e->name.size());
            packerAppend(p, ": ** NOT DISPLAYED **\r\n", 23);
        } else {
            e->packInto(p);
        }

    }
    /* Pack in the "special" entries */

    /* Cache-Control */
}

/* returns next valid entry */
HttpHeaderEntry *
HttpHeader::getEntry(HttpHeaderPos * pos) const
{
    assert(pos);
    assert(*pos >= HttpHeaderInitPos && *pos < static_cast<ssize_t>(entries.size()));

    for (++(*pos); *pos < static_cast<ssize_t>(entries.size()); ++(*pos)) {
        if (entries[*pos])
            return static_cast<HttpHeaderEntry*>(entries[*pos]);
    }

    return NULL;
}

/*
 * returns a pointer to a specified entry if any
 * note that we return one entry so it does not make much sense to ask for
 * "list" headers
 */
HttpHeaderEntry *
HttpHeader::findEntry(http_hdr_type id) const
{
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;
    assert_eid(id);
    assert(!CBIT_TEST(ListHeadersMask, id));

    /* check mask first */

    if (!CBIT_TEST(mask, id))
        return NULL;

    /* looks like we must have it, do linear search */
    while ((e = getEntry(&pos))) {
        if (e->id == id)
            return e;
    }

    /* hm.. we thought it was there, but it was not found */
    assert(0);

    return NULL;        /* not reached */
}

/*
 * same as httpHeaderFindEntry
 */
HttpHeaderEntry *
HttpHeader::findLastEntry(http_hdr_type id) const
{
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;
    HttpHeaderEntry *result = NULL;
    assert_eid(id);
    assert(!CBIT_TEST(ListHeadersMask, id));

    /* check mask first */

    if (!CBIT_TEST(mask, id))
        return NULL;

    /* looks like we must have it, do linear search */
    while ((e = getEntry(&pos))) {
        if (e->id == id)
            result = e;
    }

    assert(result);     /* must be there! */
    return result;
}

/*
 * deletes all fields with a given name if any, returns #fields deleted;
 */
int
HttpHeader::delByName(const char *name)
{
    int count = 0;
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;
    httpHeaderMaskInit(&mask, 0);   /* temporal inconsistency */
    debugs(55, 9, "deleting '" << name << "' fields in hdr " << this);

    while ((e = getEntry(&pos))) {
        if (!e->name.caseCmp(name))
            delAt(pos, count);
        else
            CBIT_SET(mask, e->id);
    }

    return count;
}

/* deletes all entries with a given id, returns the #entries deleted */
int
HttpHeader::delById(http_hdr_type id)
{
    int count = 0;
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;
    debugs(55, 8, this << " del-by-id " << id);
    assert_eid(id);
    assert(id != HDR_OTHER);        /* does not make sense */

    if (!CBIT_TEST(mask, id))
        return 0;

    while ((e = getEntry(&pos))) {
        if (e->id == id)
            delAt(pos, count);
    }

    CBIT_CLR(mask, id);
    assert(count);
    return count;
}

/*
 * deletes an entry at pos and leaves a gap; leaving a gap makes it
 * possible to iterate(search) and delete fields at the same time
 * NOTE: Does not update the header mask. Caller must follow up with
 * a call to refreshMask() if headers_deleted was incremented.
 */
void
HttpHeader::delAt(HttpHeaderPos pos, int &headers_deleted)
{
    HttpHeaderEntry *e;
    assert(pos >= HttpHeaderInitPos && pos < static_cast<ssize_t>(entries.size()));
    e = static_cast<HttpHeaderEntry*>(entries[pos]);
    entries[pos] = NULL;
    /* decrement header length, allow for ": " and crlf */
    len -= e->name.size() + 2 + e->value.size() + 2;
    assert(len >= 0);
    delete e;
    ++headers_deleted;
}

/*
 * Compacts the header storage
 */
void
HttpHeader::compact()
{
    // TODO: optimize removal, or possibly make it so that's not needed.
    std::vector<HttpHeaderEntry *>::iterator newend;
    newend = std::remove(entries.begin(), entries.end(), static_cast<HttpHeaderEntry *>(NULL));
    entries.resize(newend-entries.begin());
}

/*
 * Refreshes the header mask. Required after delAt() calls.
 */
void
HttpHeader::refreshMask()
{
    httpHeaderMaskInit(&mask, 0);
    debugs(55, 7, "refreshing the mask in hdr " << this);
    HttpHeaderPos pos = HttpHeaderInitPos;
    while (HttpHeaderEntry *e = getEntry(&pos)) {
        CBIT_SET(mask, e->id);
    }
}

/* appends an entry;
 * does not call e->clone() so one should not reuse "*e"
 */
void
HttpHeader::addEntry(HttpHeaderEntry * e)
{
    assert(e);
    assert_eid(e->id);
    assert(e->name.size());

    debugs(55, 7, this << " adding entry: " << e->id << " at " << entries.size());

    if (CBIT_TEST(mask, e->id))
        ++ Headers[e->id].stat.repCount;
    else
        CBIT_SET(mask, e->id);

    entries.push_back(e);

    /* increment header length, allow for ": " and crlf */
    len += e->name.size() + 2 + e->value.size() + 2;
}

/* inserts an entry;
 * does not call e->clone() so one should not reuse "*e"
 */
void
HttpHeader::insertEntry(HttpHeaderEntry * e)
{
    assert(e);
    assert_eid(e->id);

    debugs(55, 7, this << " adding entry: " << e->id << " at " << entries.size());

    if (CBIT_TEST(mask, e->id))
        ++ Headers[e->id].stat.repCount;
    else
        CBIT_SET(mask, e->id);

    entries.insert(entries.begin(),e);

    /* increment header length, allow for ": " and crlf */
    len += e->name.size() + 2 + e->value.size() + 2;
}

bool
HttpHeader::getList(http_hdr_type id, String *s) const
{
    HttpHeaderEntry *e;
    HttpHeaderPos pos = HttpHeaderInitPos;
    debugs(55, 9, this << " joining for id " << id);
    /* only fields from ListHeaders array can be "listed" */
    assert(CBIT_TEST(ListHeadersMask, id));

    if (!CBIT_TEST(mask, id))
        return false;

    while ((e = getEntry(&pos))) {
        if (e->id == id)
            strListAdd(s, e->value.termedBuf(), ',');
    }

    /*
     * note: we might get an empty (size==0) string if there was an "empty"
     * header. This results in an empty length String, which may have a NULL
     * buffer.
     */
    /* temporary warning: remove it? (Is it useful for diagnostics ?) */
    if (!s->size())
        debugs(55, 3, "empty list header: " << Headers[id].name << "(" << id << ")");
    else
        debugs(55, 6, this << ": joined for id " << id << ": " << s);

    return true;
}

/* return a list of entries with the same id separated by ',' and ws */
String
HttpHeader::getList(http_hdr_type id) const
{
    HttpHeaderEntry *e;
    HttpHeaderPos pos = HttpHeaderInitPos;
    debugs(55, 9, this << "joining for id " << id);
    /* only fields from ListHeaders array can be "listed" */
    assert(CBIT_TEST(ListHeadersMask, id));

    if (!CBIT_TEST(mask, id))
        return String();

    String s;

    while ((e = getEntry(&pos))) {
        if (e->id == id)
            strListAdd(&s, e->value.termedBuf(), ',');
    }

    /*
     * note: we might get an empty (size==0) string if there was an "empty"
     * header. This results in an empty length String, which may have a NULL
     * buffer.
     */
    /* temporary warning: remove it? (Is it useful for diagnostics ?) */
    if (!s.size())
        debugs(55, 3, "empty list header: " << Headers[id].name << "(" << id << ")");
    else
        debugs(55, 6, this << ": joined for id " << id << ": " << s);

    return s;
}

/* return a string or list of entries with the same id separated by ',' and ws */
String
HttpHeader::getStrOrList(http_hdr_type id) const
{
    HttpHeaderEntry *e;

    if (CBIT_TEST(ListHeadersMask, id))
        return getList(id);

    if ((e = findEntry(id)))
        return e->value;

    return String();
}

/*
 * Returns the value of the specified header and/or an undefined String.
 */
String
HttpHeader::getByName(const char *name) const
{
    String result;
    // ignore presence: return undefined string if an empty header is present
    (void)getByNameIfPresent(name, result);
    return result;
}

bool
HttpHeader::getByNameIfPresent(const char *name, String &result) const
{
    http_hdr_type id;
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;

    assert(name);

    /* First try the quick path */
    id = httpHeaderIdByNameDef(name, strlen(name));

    if (id != -1) {
        if (!has(id))
            return false;
        result = getStrOrList(id);
        return true;
    }

    /* Sorry, an unknown header name. Do linear search */
    bool found = false;
    while ((e = getEntry(&pos))) {
        if (e->id == HDR_OTHER && e->name.caseCmp(name) == 0) {
            found = true;
            strListAdd(&result, e->value.termedBuf(), ',');
        }
    }

    return found;
}

/*
 * Returns a the value of the specified list member, if any.
 */
String
HttpHeader::getByNameListMember(const char *name, const char *member, const char separator) const
{
    String header;
    const char *pos = NULL;
    const char *item;
    int ilen;
    int mlen = strlen(member);

    assert(name);

    header = getByName(name);

    String result;

    while (strListGetItem(&header, separator, &item, &ilen, &pos)) {
        if (strncmp(item, member, mlen) == 0 && item[mlen] == '=') {
            result.append(item + mlen + 1, ilen - mlen - 1);
            break;
        }
    }

    return result;
}

/*
 * returns a the value of the specified list member, if any.
 */
String
HttpHeader::getListMember(http_hdr_type id, const char *member, const char separator) const
{
    String header;
    const char *pos = NULL;
    const char *item;
    int ilen;
    int mlen = strlen(member);

    assert(id >= 0);

    header = getStrOrList(id);
    String result;

    while (strListGetItem(&header, separator, &item, &ilen, &pos)) {
        if (strncmp(item, member, mlen) == 0 && item[mlen] == '=') {
            result.append(item + mlen + 1, ilen - mlen - 1);
            break;
        }
    }

    header.clean();
    return result;
}

/* test if a field is present */
int
HttpHeader::has(http_hdr_type id) const
{
    assert_eid(id);
    assert(id != HDR_OTHER);
    debugs(55, 9, this << " lookup for " << id);
    return CBIT_TEST(mask, id);
}

void
HttpHeader::putInt(http_hdr_type id, int number)
{
    assert_eid(id);
    assert(Headers[id].type == ftInt);  /* must be of an appropriate type */
    assert(number >= 0);
    addEntry(new HttpHeaderEntry(id, NULL, xitoa(number)));
}

void
HttpHeader::putInt64(http_hdr_type id, int64_t number)
{
    assert_eid(id);
    assert(Headers[id].type == ftInt64);    /* must be of an appropriate type */
    assert(number >= 0);
    addEntry(new HttpHeaderEntry(id, NULL, xint64toa(number)));
}

void
HttpHeader::putTime(http_hdr_type id, time_t htime)
{
    assert_eid(id);
    assert(Headers[id].type == ftDate_1123);    /* must be of an appropriate type */
    assert(htime >= 0);
    addEntry(new HttpHeaderEntry(id, NULL, mkrfc1123(htime)));
}

void
HttpHeader::insertTime(http_hdr_type id, time_t htime)
{
    assert_eid(id);
    assert(Headers[id].type == ftDate_1123);    /* must be of an appropriate type */
    assert(htime >= 0);
    insertEntry(new HttpHeaderEntry(id, NULL, mkrfc1123(htime)));
}

void
HttpHeader::putStr(http_hdr_type id, const char *str)
{
    assert_eid(id);
    assert(Headers[id].type == ftStr);  /* must be of an appropriate type */
    assert(str);
    addEntry(new HttpHeaderEntry(id, NULL, str));
}

void
HttpHeader::putAuth(const char *auth_scheme, const char *realm)
{
    assert(auth_scheme && realm);
    httpHeaderPutStrf(this, HDR_WWW_AUTHENTICATE, "%s realm=\"%s\"", auth_scheme, realm);
}

void
HttpHeader::putCc(const HttpHdrCc * cc)
{
    MemBuf mb;
    Packer p;
    assert(cc);
    /* remove old directives if any */
    delById(HDR_CACHE_CONTROL);
    /* pack into mb */
    mb.init();
    packerToMemInit(&p, &mb);
    cc->packInto(&p);
    /* put */
    addEntry(new HttpHeaderEntry(HDR_CACHE_CONTROL, NULL, mb.buf));
    /* cleanup */
    packerClean(&p);
    mb.clean();
}

void
HttpHeader::putContRange(const HttpHdrContRange * cr)
{
    MemBuf mb;
    Packer p;
    assert(cr);
    /* remove old directives if any */
    delById(HDR_CONTENT_RANGE);
    /* pack into mb */
    mb.init();
    packerToMemInit(&p, &mb);
    httpHdrContRangePackInto(cr, &p);
    /* put */
    addEntry(new HttpHeaderEntry(HDR_CONTENT_RANGE, NULL, mb.buf));
    /* cleanup */
    packerClean(&p);
    mb.clean();
}

void
HttpHeader::putRange(const HttpHdrRange * range)
{
    MemBuf mb;
    Packer p;
    assert(range);
    /* remove old directives if any */
    delById(HDR_RANGE);
    /* pack into mb */
    mb.init();
    packerToMemInit(&p, &mb);
    range->packInto(&p);
    /* put */
    addEntry(new HttpHeaderEntry(HDR_RANGE, NULL, mb.buf));
    /* cleanup */
    packerClean(&p);
    mb.clean();
}

void
HttpHeader::putSc(HttpHdrSc *sc)
{
    MemBuf mb;
    Packer p;
    assert(sc);
    /* remove old directives if any */
    delById(HDR_SURROGATE_CONTROL);
    /* pack into mb */
    mb.init();
    packerToMemInit(&p, &mb);
    sc->packInto(&p);
    /* put */
    addEntry(new HttpHeaderEntry(HDR_SURROGATE_CONTROL, NULL, mb.buf));
    /* cleanup */
    packerClean(&p);
    mb.clean();
}

void
HttpHeader::putWarning(const int code, const char *const text)
{
    char buf[512];
    snprintf(buf, sizeof(buf), "%i %s \"%s\"", code, visible_appname_string, text);
    putStr(HDR_WARNING, buf);
}

/* add extension header (these fields are not parsed/analyzed/joined, etc.) */
void
HttpHeader::putExt(const char *name, const char *value)
{
    assert(name && value);
    debugs(55, 8, this << " adds ext entry " << name << " : " << value);
    addEntry(new HttpHeaderEntry(HDR_OTHER, name, value));
}

int
HttpHeader::getInt(http_hdr_type id) const
{
    assert_eid(id);
    assert(Headers[id].type == ftInt);  /* must be of an appropriate type */
    HttpHeaderEntry *e;

    if ((e = findEntry(id)))
        return e->getInt();

    return -1;
}

int64_t
HttpHeader::getInt64(http_hdr_type id) const
{
    assert_eid(id);
    assert(Headers[id].type == ftInt64);    /* must be of an appropriate type */
    HttpHeaderEntry *e;

    if ((e = findEntry(id)))
        return e->getInt64();

    return -1;
}

time_t
HttpHeader::getTime(http_hdr_type id) const
{
    HttpHeaderEntry *e;
    time_t value = -1;
    assert_eid(id);
    assert(Headers[id].type == ftDate_1123);    /* must be of an appropriate type */

    if ((e = findEntry(id))) {
        value = parse_rfc1123(e->value.termedBuf());
        httpHeaderNoteParsedEntry(e->id, e->value, value < 0);
    }

    return value;
}

/* sync with httpHeaderGetLastStr */
const char *
HttpHeader::getStr(http_hdr_type id) const
{
    HttpHeaderEntry *e;
    assert_eid(id);
    assert(Headers[id].type == ftStr);  /* must be of an appropriate type */

    if ((e = findEntry(id))) {
        httpHeaderNoteParsedEntry(e->id, e->value, 0);  /* no errors are possible */
        return e->value.termedBuf();
    }

    return NULL;
}

/* unusual */
const char *
HttpHeader::getLastStr(http_hdr_type id) const
{
    HttpHeaderEntry *e;
    assert_eid(id);
    assert(Headers[id].type == ftStr);  /* must be of an appropriate type */

    if ((e = findLastEntry(id))) {
        httpHeaderNoteParsedEntry(e->id, e->value, 0);  /* no errors are possible */
        return e->value.termedBuf();
    }

    return NULL;
}

HttpHdrCc *
HttpHeader::getCc() const
{
    if (!CBIT_TEST(mask, HDR_CACHE_CONTROL))
        return NULL;
    PROF_start(HttpHeader_getCc);

    String s;
    getList(HDR_CACHE_CONTROL, &s);

    HttpHdrCc *cc=new HttpHdrCc();

    if (!cc->parse(s)) {
        delete cc;
        cc = NULL;
    }

    ++ HttpHeaderStats[owner].ccParsedCount;

    if (cc)
        httpHdrCcUpdateStats(cc, &HttpHeaderStats[owner].ccTypeDistr);

    httpHeaderNoteParsedEntry(HDR_CACHE_CONTROL, s, !cc);

    PROF_stop(HttpHeader_getCc);

    return cc;
}

HttpHdrRange *
HttpHeader::getRange() const
{
    HttpHdrRange *r = NULL;
    HttpHeaderEntry *e;
    /* some clients will send "Request-Range" _and_ *matching* "Range"
     * who knows, some clients might send Request-Range only;
     * this "if" should work correctly in both cases;
     * hopefully no clients send mismatched headers! */

    if ((e = findEntry(HDR_RANGE)) ||
            (e = findEntry(HDR_REQUEST_RANGE))) {
        r = HttpHdrRange::ParseCreate(&e->value);
        httpHeaderNoteParsedEntry(e->id, e->value, !r);
    }

    return r;
}

HttpHdrSc *
HttpHeader::getSc() const
{
    if (!CBIT_TEST(mask, HDR_SURROGATE_CONTROL))
        return NULL;

    String s;

    (void) getList(HDR_SURROGATE_CONTROL, &s);

    HttpHdrSc *sc = httpHdrScParseCreate(s);

    ++ HttpHeaderStats[owner].ccParsedCount;

    if (sc)
        sc->updateStats(&HttpHeaderStats[owner].scTypeDistr);

    httpHeaderNoteParsedEntry(HDR_SURROGATE_CONTROL, s, !sc);

    return sc;
}

HttpHdrContRange *
HttpHeader::getContRange() const
{
    HttpHdrContRange *cr = NULL;
    HttpHeaderEntry *e;

    if ((e = findEntry(HDR_CONTENT_RANGE))) {
        cr = httpHdrContRangeParseCreate(e->value.termedBuf());
        httpHeaderNoteParsedEntry(e->id, e->value, !cr);
    }

    return cr;
}

const char *
HttpHeader::getAuth(http_hdr_type id, const char *auth_scheme) const
{
    const char *field;
    int l;
    assert(auth_scheme);
    field = getStr(id);

    if (!field)         /* no authorization field */
        return NULL;

    l = strlen(auth_scheme);

    if (!l || strncasecmp(field, auth_scheme, l))   /* wrong scheme */
        return NULL;

    field += l;

    if (!xisspace(*field))  /* wrong scheme */
        return NULL;

    /* skip white space */
    for (; field && xisspace(*field); ++field);

    if (!*field)        /* no authorization cookie */
        return NULL;

    static char decodedAuthToken[8192];
    const int decodedLen = base64_decode(decodedAuthToken, sizeof(decodedAuthToken)-1, field);
    decodedAuthToken[decodedLen] = '\0';
    return decodedAuthToken;
}

ETag
HttpHeader::getETag(http_hdr_type id) const
{
    ETag etag = {NULL, -1};
    HttpHeaderEntry *e;
    assert(Headers[id].type == ftETag);     /* must be of an appropriate type */

    if ((e = findEntry(id)))
        etagParseInit(&etag, e->value.termedBuf());

    return etag;
}

TimeOrTag
HttpHeader::getTimeOrTag(http_hdr_type id) const
{
    TimeOrTag tot;
    HttpHeaderEntry *e;
    assert(Headers[id].type == ftDate_1123_or_ETag);    /* must be of an appropriate type */
    memset(&tot, 0, sizeof(tot));

    if ((e = findEntry(id))) {
        const char *str = e->value.termedBuf();
        /* try as an ETag */

        if (etagParseInit(&tot.tag, str)) {
            tot.valid = tot.tag.str != NULL;
            tot.time = -1;
        } else {
            /* or maybe it is time? */
            tot.time = parse_rfc1123(str);
            tot.valid = tot.time >= 0;
            tot.tag.str = NULL;
        }
    }

    assert(tot.time < 0 || !tot.tag.str);   /* paranoid */
    return tot;
}

/*
 * HttpHeaderEntry
 */

HttpHeaderEntry::HttpHeaderEntry(http_hdr_type anId, const char *aName, const char *aValue)
{
    assert_eid(anId);
    id = anId;

    if (id != HDR_OTHER)
        name = Headers[id].name;
    else
        name = aName;

    value = aValue;

    ++ Headers[id].stat.aliveCount;

    debugs(55, 9, "created HttpHeaderEntry " << this << ": '" << name << " : " << value );
}

HttpHeaderEntry::~HttpHeaderEntry()
{
    assert_eid(id);
    debugs(55, 9, "destroying entry " << this << ": '" << name << ": " << value << "'");
    /* clean name if needed */

    if (id == HDR_OTHER)
        name.clean();

    value.clean();

    assert(Headers[id].stat.aliveCount);

    -- Headers[id].stat.aliveCount;

    id = HDR_BAD_HDR;
}

/* parses and inits header entry, returns true/false */
HttpHeaderEntry *
HttpHeaderEntry::parse(const char *field_start, const char *field_end)
{
    /* note: name_start == field_start */
    const char *name_end = (const char *)memchr(field_start, ':', field_end - field_start);
    int name_len = name_end ? name_end - field_start :0;
    const char *value_start = field_start + name_len + 1;   /* skip ':' */
    /* note: value_end == field_end */

    ++ HeaderEntryParsedCount;

    /* do we have a valid field name within this field? */

    if (!name_len || name_end > field_end)
        return NULL;

    if (name_len > 65534) {
        /* String must be LESS THAN 64K and it adds a terminating NULL */
        debugs(55, DBG_IMPORTANT, "WARNING: ignoring header name of " << name_len << " bytes");
        return NULL;
    }

    if (Config.onoff.relaxed_header_parser && xisspace(field_start[name_len - 1])) {
        debugs(55, Config.onoff.relaxed_header_parser <= 0 ? 1 : 2,
               "NOTICE: Whitespace after header name in '" << getStringPrefix(field_start, field_end) << "'");

        while (name_len > 0 && xisspace(field_start[name_len - 1]))
            --name_len;

        if (!name_len)
            return NULL;
    }

    /* now we know we can parse it */

    debugs(55, 9, "parsing HttpHeaderEntry: near '" <<  getStringPrefix(field_start, field_end) << "'");

    /* is it a "known" field? */
    http_hdr_type id = httpHeaderIdByName(field_start, name_len, Headers, HDR_ENUM_END);

    String name;

    String value;

    if (id < 0)
        id = HDR_OTHER;

    assert_eid(id);

    /* set field name */
    if (id == HDR_OTHER)
        name.limitInit(field_start, name_len);
    else
        name = Headers[id].name;

    /* trim field value */
    while (value_start < field_end && xisspace(*value_start))
        ++value_start;

    while (value_start < field_end && xisspace(field_end[-1]))
        --field_end;

    if (field_end - value_start > 65534) {
        /* String must be LESS THAN 64K and it adds a terminating NULL */
        debugs(55, DBG_IMPORTANT, "WARNING: ignoring '" << name << "' header of " << (field_end - value_start) << " bytes");

        if (id == HDR_OTHER)
            name.clean();

        return NULL;
    }

    /* set field value */
    value.limitInit(value_start, field_end - value_start);

    ++ Headers[id].stat.seenCount;

    debugs(55, 9, "parsed HttpHeaderEntry: '" << name << ": " << value << "'");

    return new HttpHeaderEntry(id, name.termedBuf(), value.termedBuf());
}

HttpHeaderEntry *
HttpHeaderEntry::clone() const
{
    return new HttpHeaderEntry(id, name.termedBuf(), value.termedBuf());
}

void
HttpHeaderEntry::packInto(Packer * p) const
{
    assert(p);
    packerAppend(p, name.rawBuf(), name.size());
    packerAppend(p, ": ", 2);
    packerAppend(p, value.rawBuf(), value.size());
    packerAppend(p, "\r\n", 2);
}

int
HttpHeaderEntry::getInt() const
{
    assert_eid (id);
    int val = -1;
    int ok = httpHeaderParseInt(value.termedBuf(), &val);
    httpHeaderNoteParsedEntry(id, value, !ok);
    /* XXX: Should we check ok - ie
     * return ok ? -1 : value;
     */
    return val;
}

int64_t
HttpHeaderEntry::getInt64() const
{
    assert_eid (id);
    int64_t val = -1;
    int ok = httpHeaderParseOffset(value.termedBuf(), &val);
    httpHeaderNoteParsedEntry(id, value, !ok);
    /* XXX: Should we check ok - ie
     * return ok ? -1 : value;
     */
    return val;
}

static void
httpHeaderNoteParsedEntry(http_hdr_type id, String const &context, int error)
{
    ++ Headers[id].stat.parsCount;

    if (error) {
        ++ Headers[id].stat.errCount;
        debugs(55, 2, "cannot parse hdr field: '" << Headers[id].name << ": " << context << "'");
    }
}

/*
 * Reports
 */

/* tmp variable used to pass stat info to dumpers */
extern const HttpHeaderStat *dump_stat;     /* argh! */
const HttpHeaderStat *dump_stat = NULL;

void
httpHeaderFieldStatDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    const int id = (int) val;
    const int valid_id = id >= 0 && id < HDR_ENUM_END;
    const char *name = valid_id ? Headers[id].name.termedBuf() : "INVALID";
    int visible = count > 0;
    /* for entries with zero count, list only those that belong to current type of message */

    if (!visible && valid_id && dump_stat->owner_mask)
        visible = CBIT_TEST(*dump_stat->owner_mask, id);

    if (visible)
        storeAppendPrintf(sentry, "%2d\t %-20s\t %5d\t %6.2f\n",
                          id, name, count, xdiv(count, dump_stat->busyDestroyedCount));
}

static void
httpHeaderFldsPerHdrDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    if (count)
        storeAppendPrintf(sentry, "%2d\t %5d\t %5d\t %6.2f\n",
                          idx, (int) val, count,
                          xpercent(count, dump_stat->destroyedCount));
}

static void
httpHeaderStatDump(const HttpHeaderStat * hs, StoreEntry * e)
{
    assert(hs && e);

    dump_stat = hs;
    storeAppendPrintf(e, "\nHeader Stats: %s\n", hs->label);
    storeAppendPrintf(e, "\nField type distribution\n");
    storeAppendPrintf(e, "%2s\t %-20s\t %5s\t %6s\n",
                      "id", "name", "count", "#/header");
    hs->fieldTypeDistr.dump(e, httpHeaderFieldStatDumper);
    storeAppendPrintf(e, "\nCache-control directives distribution\n");
    storeAppendPrintf(e, "%2s\t %-20s\t %5s\t %6s\n",
                      "id", "name", "count", "#/cc_field");
    hs->ccTypeDistr.dump(e, httpHdrCcStatDumper);
    storeAppendPrintf(e, "\nSurrogate-control directives distribution\n");
    storeAppendPrintf(e, "%2s\t %-20s\t %5s\t %6s\n",
                      "id", "name", "count", "#/sc_field");
    hs->scTypeDistr.dump(e, httpHdrScStatDumper);
    storeAppendPrintf(e, "\nNumber of fields per header distribution\n");
    storeAppendPrintf(e, "%2s\t %-5s\t %5s\t %6s\n",
                      "id", "#flds", "count", "%total");
    hs->hdrUCountDistr.dump(e, httpHeaderFldsPerHdrDumper);
    storeAppendPrintf(e, "\n");
    dump_stat = NULL;
}

void
httpHeaderStoreReport(StoreEntry * e)
{
    int i;
    http_hdr_type ht;
    assert(e);

    HttpHeaderStats[0].parsedCount =
        HttpHeaderStats[hoRequest].parsedCount + HttpHeaderStats[hoReply].parsedCount;
    HttpHeaderStats[0].ccParsedCount =
        HttpHeaderStats[hoRequest].ccParsedCount + HttpHeaderStats[hoReply].ccParsedCount;
    HttpHeaderStats[0].destroyedCount =
        HttpHeaderStats[hoRequest].destroyedCount + HttpHeaderStats[hoReply].destroyedCount;
    HttpHeaderStats[0].busyDestroyedCount =
        HttpHeaderStats[hoRequest].busyDestroyedCount + HttpHeaderStats[hoReply].busyDestroyedCount;

    for (i = 1; i < HttpHeaderStatCount; ++i) {
        httpHeaderStatDump(HttpHeaderStats + i, e);
    }

    /* field stats for all messages */
    storeAppendPrintf(e, "\nHttp Fields Stats (replies and requests)\n");

    storeAppendPrintf(e, "%2s\t %-25s\t %5s\t %6s\t %6s\n",
                      "id", "name", "#alive", "%err", "%repeat");

    for (ht = (http_hdr_type)0; ht < HDR_ENUM_END; ++ht) {
        HttpHeaderFieldInfo *f = Headers + ht;
        storeAppendPrintf(e, "%2d\t %-25s\t %5d\t %6.3f\t %6.3f\n",
                          f->id, f->name.termedBuf(), f->stat.aliveCount,
                          xpercent(f->stat.errCount, f->stat.parsCount),
                          xpercent(f->stat.repCount, f->stat.seenCount));
    }

    storeAppendPrintf(e, "Headers Parsed: %d + %d = %d\n",
                      HttpHeaderStats[hoRequest].parsedCount,
                      HttpHeaderStats[hoReply].parsedCount,
                      HttpHeaderStats[0].parsedCount);
    storeAppendPrintf(e, "Hdr Fields Parsed: %d\n", HeaderEntryParsedCount);
}

http_hdr_type
httpHeaderIdByName(const char *name, size_t name_len, const HttpHeaderFieldInfo * info, int end)
{
    if (name_len > 0) {
        for (int i = 0; i < end; ++i) {
            if (name_len != info[i].name.size())
                continue;

            if (!strncasecmp(name, info[i].name.rawBuf(), name_len))
                return info[i].id;
        }
    }

    return HDR_BAD_HDR;
}

http_hdr_type
httpHeaderIdByNameDef(const char *name, int name_len)
{
    if (!Headers)
        Headers = httpHeaderBuildFieldsInfo(HeadersAttrs, HDR_ENUM_END);

    return httpHeaderIdByName(name, name_len, Headers, HDR_ENUM_END);
}

const char *
httpHeaderNameById(int id)
{
    if (!Headers)
        Headers = httpHeaderBuildFieldsInfo(HeadersAttrs, HDR_ENUM_END);

    assert(id >= 0 && id < HDR_ENUM_END);

    return Headers[id].name.termedBuf();
}

int
HttpHeader::hasListMember(http_hdr_type id, const char *member, const char separator) const
{
    int result = 0;
    const char *pos = NULL;
    const char *item;
    int ilen;
    int mlen = strlen(member);

    assert(id >= 0);

    String header (getStrOrList(id));

    while (strListGetItem(&header, separator, &item, &ilen, &pos)) {
        if (strncasecmp(item, member, mlen) == 0
                && (item[mlen] == '=' || item[mlen] == separator || item[mlen] == ';' || item[mlen] == '\0')) {
            result = 1;
            break;
        }
    }

    return result;
}

int
HttpHeader::hasByNameListMember(const char *name, const char *member, const char separator) const
{
    int result = 0;
    const char *pos = NULL;
    const char *item;
    int ilen;
    int mlen = strlen(member);

    assert(name);

    String header (getByName(name));

    while (strListGetItem(&header, separator, &item, &ilen, &pos)) {
        if (strncasecmp(item, member, mlen) == 0
                && (item[mlen] == '=' || item[mlen] == separator || item[mlen] == ';' || item[mlen] == '\0')) {
            result = 1;
            break;
        }
    }

    return result;
}

void
HttpHeader::removeHopByHopEntries()
{
    removeConnectionHeaderEntries();

    const HttpHeaderEntry *e;
    HttpHeaderPos pos = HttpHeaderInitPos;
    int headers_deleted = 0;
    while ((e = getEntry(&pos))) {
        int id = e->id;
        if (CBIT_TEST(HopByHopHeadersMask, id)) {
            delAt(pos, headers_deleted);
            CBIT_CLR(mask, id);
        }
    }
}

void
HttpHeader::removeConnectionHeaderEntries()
{
    if (has(HDR_CONNECTION)) {
        /* anything that matches Connection list member will be deleted */
        String strConnection;

        (void) getList(HDR_CONNECTION, &strConnection);
        const HttpHeaderEntry *e;
        HttpHeaderPos pos = HttpHeaderInitPos;
        /*
         * think: on-average-best nesting of the two loops (hdrEntry
         * and strListItem) @?@
         */
        /*
         * maybe we should delete standard stuff ("keep-alive","close")
         * from strConnection first?
         */

        int headers_deleted = 0;
        while ((e = getEntry(&pos))) {
            if (strListIsMember(&strConnection, e->name.termedBuf(), ','))
                delAt(pos, headers_deleted);
        }
        if (headers_deleted)
            refreshMask();
    }
}

