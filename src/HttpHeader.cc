/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 55    HTTP Header */

#include "squid.h"
#include "base/LookupTable.h"
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
#include "util.h"

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

// statistics counters for headers. clients must not allow Http::HdrType::BAD_HDR to be counted
std::vector<HttpHeaderFieldStat> headerStatsTable(Http::HdrType::ENUM_END);

/*
 * headers with field values defined as #(values) in HTTP/1.1
 * Headers that are currently not recognized, are commented out.
 */
static HttpHeaderMask ListHeadersMask;  /* set run-time using  ListHeadersArr */
static Http::HdrType ListHeadersArr[] = {
    Http::HdrType::ACCEPT,
    Http::HdrType::ACCEPT_CHARSET,
    Http::HdrType::ACCEPT_ENCODING,
    Http::HdrType::ACCEPT_LANGUAGE,
    Http::HdrType::ACCEPT_RANGES,
    Http::HdrType::ALLOW,
    Http::HdrType::CACHE_CONTROL,
    Http::HdrType::CONTENT_ENCODING,
    Http::HdrType::CONTENT_LANGUAGE,
    Http::HdrType::CONNECTION,
    Http::HdrType::EXPECT,
    Http::HdrType::IF_MATCH,
    Http::HdrType::IF_NONE_MATCH,
    Http::HdrType::KEY,
    Http::HdrType::LINK,
    Http::HdrType::PRAGMA,
    Http::HdrType::PROXY_CONNECTION,
    Http::HdrType::PROXY_SUPPORT,
    Http::HdrType::TRANSFER_ENCODING,
    Http::HdrType::UPGRADE,
    Http::HdrType::VARY,
    Http::HdrType::VIA,
    Http::HdrType::WARNING,
    Http::HdrType::WWW_AUTHENTICATE,
    Http::HdrType::AUTHENTICATION_INFO,
    Http::HdrType::PROXY_AUTHENTICATION_INFO,
    /* Http::HdrType::TE, Http::HdrType::TRAILER */
#if X_ACCELERATOR_VARY
    Http::HdrType::HDR_X_ACCELERATOR_VARY,
#endif
#if USE_ADAPTATION
    Http::HdrType::X_NEXT_SERVICES,
#endif
    Http::HdrType::SURROGATE_CAPABILITY,
    Http::HdrType::SURROGATE_CONTROL,
    Http::HdrType::FORWARDED,
    Http::HdrType::X_FORWARDED_FOR
};

/* general-headers */
static Http::HdrType GeneralHeadersArr[] = {
    Http::HdrType::CACHE_CONTROL,
    Http::HdrType::CONNECTION,
    Http::HdrType::DATE,
    Http::HdrType::FORWARDED,
    Http::HdrType::X_FORWARDED_FOR,
    Http::HdrType::MIME_VERSION,
    Http::HdrType::PRAGMA,
    Http::HdrType::PROXY_CONNECTION,
    Http::HdrType::TRANSFER_ENCODING,
    Http::HdrType::UPGRADE,
    /* Http::HdrType::TRAILER, */
    Http::HdrType::VIA,
};

/* entity-headers */
static Http::HdrType EntityHeadersArr[] = {
    Http::HdrType::ALLOW,
    Http::HdrType::CONTENT_BASE,
    Http::HdrType::CONTENT_ENCODING,
    Http::HdrType::CONTENT_LANGUAGE,
    Http::HdrType::CONTENT_LENGTH,
    Http::HdrType::CONTENT_LOCATION,
    Http::HdrType::CONTENT_MD5,
    Http::HdrType::CONTENT_RANGE,
    Http::HdrType::CONTENT_TYPE,
    Http::HdrType::ETAG,
    Http::HdrType::EXPIRES,
    Http::HdrType::LAST_MODIFIED,
    Http::HdrType::LINK,
    Http::HdrType::OTHER
};

/* request-only headers */
static HttpHeaderMask RequestHeadersMask;   /* set run-time using RequestHeaders */
static Http::HdrType RequestHeadersArr[] = {
    Http::HdrType::ACCEPT,
    Http::HdrType::ACCEPT_CHARSET,
    Http::HdrType::ACCEPT_ENCODING,
    Http::HdrType::ACCEPT_LANGUAGE,
    Http::HdrType::AUTHORIZATION,
    Http::HdrType::EXPECT,
    Http::HdrType::FROM,
    Http::HdrType::HOST,
    Http::HdrType::HTTP2_SETTINGS,
    Http::HdrType::IF_MATCH,
    Http::HdrType::IF_MODIFIED_SINCE,
    Http::HdrType::IF_NONE_MATCH,
    Http::HdrType::IF_RANGE,
    Http::HdrType::IF_UNMODIFIED_SINCE,
    Http::HdrType::MAX_FORWARDS,
    Http::HdrType::ORIGIN,
    Http::HdrType::PROXY_AUTHORIZATION,
    Http::HdrType::RANGE,
    Http::HdrType::REFERER,
    Http::HdrType::REQUEST_RANGE,
    Http::HdrType::TE,
    Http::HdrType::USER_AGENT,
    Http::HdrType::SURROGATE_CAPABILITY
};

/* reply-only headers */
static HttpHeaderMask ReplyHeadersMask;     /* set run-time using ReplyHeaders */
static Http::HdrType ReplyHeadersArr[] = {
    Http::HdrType::ACCEPT_ENCODING,
    Http::HdrType::ACCEPT_RANGES,
    Http::HdrType::AGE,
    Http::HdrType::KEY,
    Http::HdrType::LOCATION,
    Http::HdrType::PROXY_AUTHENTICATE,
    Http::HdrType::PUBLIC,
    Http::HdrType::RETRY_AFTER,
    Http::HdrType::SERVER,
    Http::HdrType::SET_COOKIE,
    Http::HdrType::SET_COOKIE2,
    Http::HdrType::VARY,
    Http::HdrType::WARNING,
    Http::HdrType::WWW_AUTHENTICATE,
    Http::HdrType::X_CACHE,
    Http::HdrType::X_CACHE_LOOKUP,
    Http::HdrType::X_REQUEST_URI,
#if X_ACCELERATOR_VARY
    Http::HdrType::HDR_X_ACCELERATOR_VARY,
#endif
#if USE_ADAPTATION
    Http::HdrType::X_NEXT_SERVICES,
#endif
    Http::HdrType::X_SQUID_ERROR,
    Http::HdrType::SURROGATE_CONTROL
};

/* hop-by-hop headers */
static HttpHeaderMask HopByHopHeadersMask;
static Http::HdrType HopByHopHeadersArr[] = {
    Http::HdrType::ALTERNATE_PROTOCOL,
    Http::HdrType::CONNECTION,
    Http::HdrType::HTTP2_SETTINGS,
    Http::HdrType::KEEP_ALIVE,
    /*Http::HdrType::PROXY_AUTHENTICATE, // removal handled specially for peer login */
    Http::HdrType::PROXY_AUTHORIZATION,
    Http::HdrType::TE,
    Http::HdrType::TRAILER,
    Http::HdrType::TRANSFER_ENCODING,
    Http::HdrType::UPGRADE,
    Http::HdrType::PROXY_CONNECTION
};

/* header accounting */
// NP: keep in sync with enum http_hdr_owner_type
static HttpHeaderStat HttpHeaderStats[] = {
    HttpHeaderStat(/*hoNone*/ "all", NULL),
#if USE_HTCP
    HttpHeaderStat(/*hoHtcpReply*/ "HTCP reply", &ReplyHeadersMask),
#endif
    HttpHeaderStat(/*hoRequest*/ "request", &RequestHeadersMask),
    HttpHeaderStat(/*hoReply*/ "reply", &ReplyHeadersMask)
#if USE_OPENSSL
    /* hoErrorDetail */
#endif
    /* hoEnd */
};
static int HttpHeaderStatCount = countof(HttpHeaderStats);

static int HeaderEntryParsedCount = 0;

/*
 * forward declarations and local routines
 */

class StoreEntry;

static inline
bool
any_registered_header (const Http::HdrType id)
{
    return (id == Http::HdrType::BAD_HDR || (id >= Http::HdrType::ACCEPT && id < Http::HdrType::ENUM_END));
}

static inline
bool
any_valid_header (const Http::HdrType id)
{
    return (id >= Http::HdrType::ACCEPT && id < Http::HdrType::ENUM_END);
}

static void httpHeaderNoteParsedEntry(Http::HdrType id, String const &value, int error);
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
    /* check that we have enough space for masks */
    assert(8 * sizeof(HttpHeaderMask) >= Http::HdrType::ENUM_END);

    // check invariant: for each index in headerTable, (int)headerTable[index] = index
    for (int i = 0; headerTable[i].name; ++i)
        assert(headerTable[i].id == i);

    /* create masks. XXX: migrate to std::vector<bool>? */
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

    /* header stats initialized by class constructor */
    assert(HttpHeaderStatCount == hoReply + 1);

    /* init dependent modules */
    httpHdrCcInitModule();
    httpHdrScInitModule();

    httpHeaderRegisterWithCacheManager();
}

void
httpHeaderCleanModule(void)
{
    httpHdrCcCleanModule();
    httpHdrScCleanModule();
}

/*
 * HttpHeader Implementation
 */

HttpHeader::HttpHeader() : owner (hoNone), len (0)
{
    httpHeaderMaskInit(&mask, 0);
}

HttpHeader::HttpHeader(const http_hdr_owner_type anOwner): owner(anOwner), len(0)
{
    assert(anOwner > hoNone && anOwner < hoEnd);
    debugs(55, 7, "init-ing hdr: " << this << " owner: " << owner);
    httpHeaderMaskInit(&mask, 0);
}

HttpHeader::HttpHeader(const HttpHeader &other): owner(other.owner), len(other.len)
{
    httpHeaderMaskInit(&mask, 0);
    update(&other, NULL); // will update the mask as well
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
        update(&other, NULL); // will update the mask as well
        len = other.len;
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
        if (e->id >= Http::HdrType::ENUM_END) {
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

/* use fresh entries to replace old ones */
void
httpHeaderUpdate(HttpHeader * old, const HttpHeader * fresh, const HttpHeaderMask * denied_mask)
{
    assert (old);
    old->update (fresh, denied_mask);
}

void
HttpHeader::update (HttpHeader const *fresh, HttpHeaderMask const *denied_mask)
{
    const HttpHeaderEntry *e;
    HttpHeaderPos pos = HttpHeaderInitPos;
    assert(fresh);
    assert(this != fresh);

    while ((e = fresh->getEntry(&pos))) {
        /* deny bad guys (ok to check for Http::HdrType::OTHER) here */

        if (denied_mask && CBIT_TEST(*denied_mask, e->id))
            continue;

        if (e->id != Http::HdrType::OTHER)
            delById(e->id);
        else
            delByName(e->name.termedBuf());
    }

    pos = HttpHeaderInitPos;
    while ((e = fresh->getEntry(&pos))) {
        /* deny bad guys (ok to check for Http::HdrType::OTHER) here */

        if (denied_mask && CBIT_TEST(*denied_mask, e->id))
            continue;

        debugs(55, 7, "Updating header '" << headerTable[e->id].name << "' in cached entry");

        addEntry(e->clone());
    }
}

/* just handy in parsing: resets and returns false */
int
HttpHeader::reset()
{
    clean();
    return 0;
}

int
HttpHeader::parse(const char *header_start, size_t hdrLen)
{
    const char *field_ptr = header_start;
    const char *header_end = header_start + hdrLen; // XXX: remove
    HttpHeaderEntry *e, *e2;
    int warnOnError = (Config.onoff.relaxed_header_parser <= 0 ? DBG_IMPORTANT : 2);

    PROF_start(HttpHeaderParse);

    assert(header_start && header_end);
    debugs(55, 7, "parsing hdr: (" << this << ")" << std::endl << getStringPrefix(header_start, hdrLen));
    ++ HttpHeaderStats[owner].parsedCount;

    char *nulpos;
    if ((nulpos = (char*)memchr(header_start, '\0', hdrLen))) {
        debugs(55, DBG_IMPORTANT, "WARNING: HTTP header contains NULL characters {" <<
               getStringPrefix(header_start, nulpos-header_start) << "}\nNULL\n{" << getStringPrefix(nulpos+1, hdrLen-(nulpos-header_start)-1));
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
                               getStringPrefix(header_start, hdrLen) << "}");
                        PROF_stop(HttpHeaderParse);
                        return reset();
                    }
                }
            }

            /* Barf on stray CR characters */
            if (memchr(this_line, '\r', field_end - this_line)) {
                debugs(55, warnOnError, "WARNING: suspicious CR characters in HTTP header {" <<
                       getStringPrefix(field_start, field_end-field_start) << "}");

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
                       getStringPrefix(header_start, hdrLen) << "}");
                PROF_stop(HttpHeaderParse);
                return reset();
            }
        } while (field_ptr < header_end && (*field_ptr == ' ' || *field_ptr == '\t'));

        if (field_start == field_end) {
            if (field_ptr < header_end) {
                debugs(55, warnOnError, "WARNING: unparseable HTTP header field near {" <<
                       getStringPrefix(field_start, hdrLen-(field_start-header_start)) << "}");
                PROF_stop(HttpHeaderParse);
                return reset();
            }

            break;      /* terminating blank line */
        }

        if ((e = HttpHeaderEntry::parse(field_start, field_end)) == NULL) {
            debugs(55, warnOnError, "WARNING: unparseable HTTP header field {" <<
                   getStringPrefix(field_start, field_end-field_start) << "}");
            debugs(55, warnOnError, " in {" << getStringPrefix(header_start, hdrLen) << "}");

            if (Config.onoff.relaxed_header_parser)
                continue;

            PROF_stop(HttpHeaderParse);
            return reset();
        }

        if (e->id == Http::HdrType::CONTENT_LENGTH && (e2 = findEntry(e->id)) != NULL) {
            if (e->value != e2->value) {
                int64_t l1, l2;
                debugs(55, warnOnError, "WARNING: found two conflicting content-length headers in {" <<
                       getStringPrefix(header_start, hdrLen) << "}");

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
                } else if (l1 > l2) {
                    delById(e2->id);
                } else {
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

        if (e->id == Http::HdrType::OTHER && stringHasWhitespace(e->name.termedBuf())) {
            debugs(55, warnOnError, "WARNING: found whitespace in HTTP header name {" <<
                   getStringPrefix(field_start, field_end-field_start) << "}");

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
        delById(Http::HdrType::CONTENT_LENGTH);
    }

    PROF_stop(HttpHeaderParse);
    return 1;           /* even if no fields where found, it is a valid header */
}

/* packs all the entries using supplied packer */
void
HttpHeader::packInto(Packable * p, bool mask_sensitive_info) const
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
        case Http::HdrType::AUTHORIZATION:
        case Http::HdrType::PROXY_AUTHORIZATION:
            maskThisEntry = true;
            break;

        case Http::HdrType::FTP_ARGUMENTS:
            if (const HttpHeaderEntry *cmd = findEntry(Http::HdrType::FTP_COMMAND))
                maskThisEntry = (cmd->value == "PASS");
            break;

        default:
            break;
        }
        if (maskThisEntry) {
            p->append(e->name.rawBuf(), e->name.size());
            p->append(": ** NOT DISPLAYED **\r\n", 23);
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
HttpHeader::findEntry(Http::HdrType id) const
{
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;
    assert(any_valid_header(id));
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
HttpHeader::findLastEntry(Http::HdrType id) const
{
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;
    HttpHeaderEntry *result = NULL;
    assert(any_valid_header(id));
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
HttpHeader::delById(Http::HdrType id)
{
    int count = 0;
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;
    debugs(55, 8, this << " del-by-id " << id);
    assert(any_valid_header(id));
    assert(id != Http::HdrType::OTHER);        /* does not make sense */

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
    assert(any_registered_header(e->id));
    assert(e->name.size());

    debugs(55, 7, this << " adding entry: " << e->id << " at " << entries.size());

    if (e->id != Http::HdrType::BAD_HDR) {
        if (CBIT_TEST(mask, e->id)) {
            ++ headerStatsTable[e->id].repCount;
        } else {
            CBIT_SET(mask, e->id);
        }
    }

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
    assert(any_valid_header(e->id));

    debugs(55, 7, this << " adding entry: " << e->id << " at " << entries.size());

    // Http::HdrType::BAD_HDR is filtered out by assert_any_valid_header
    if (CBIT_TEST(mask, e->id)) {
        ++ headerStatsTable[e->id].repCount;
    } else {
        CBIT_SET(mask, e->id);
    }

    entries.insert(entries.begin(),e);

    /* increment header length, allow for ": " and crlf */
    len += e->name.size() + 2 + e->value.size() + 2;
}

bool
HttpHeader::getList(Http::HdrType id, String *s) const
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
        debugs(55, 3, "empty list header: " << headerTable[id].name << "(" << id << ")");
    else
        debugs(55, 6, this << ": joined for id " << id << ": " << s);

    return true;
}

/* return a list of entries with the same id separated by ',' and ws */
String
HttpHeader::getList(Http::HdrType id) const
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
        debugs(55, 3, "empty list header: " << headerTable[id].name << "(" << id << ")");
    else
        debugs(55, 6, this << ": joined for id " << id << ": " << s);

    return s;
}

/* return a string or list of entries with the same id separated by ',' and ws */
String
HttpHeader::getStrOrList(Http::HdrType id) const
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
    Http::HdrType id;
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;

    assert(name);

    /* First try the quick path */
    id = HeaderLookupTable.lookup(SBuf(name));

    if (id != Http::HdrType::BAD_HDR) {
        if (!has(id))
            return false;
        result = getStrOrList(id);
        return true;
    }

    /* Sorry, an unknown header name. Do linear search */
    bool found = false;
    while ((e = getEntry(&pos))) {
        if (e->id == Http::HdrType::OTHER && e->name.caseCmp(name) == 0) {
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
HttpHeader::getListMember(Http::HdrType id, const char *member, const char separator) const
{
    String header;
    const char *pos = NULL;
    const char *item;
    int ilen;
    int mlen = strlen(member);

    assert(any_valid_header(id));

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
HttpHeader::has(Http::HdrType id) const
{
    assert(any_valid_header(id));
    assert(id != Http::HdrType::OTHER);
    debugs(55, 9, this << " lookup for " << id);
    return CBIT_TEST(mask, id);
}

void
HttpHeader::putInt(Http::HdrType id, int number)
{
    assert(any_valid_header(id));
    assert(headerTable[id].type == Http::HdrFieldType::ftInt);  /* must be of an appropriate type */
    assert(number >= 0);
    addEntry(new HttpHeaderEntry(id, NULL, xitoa(number)));
}

void
HttpHeader::putInt64(Http::HdrType id, int64_t number)
{
    assert(any_valid_header(id));
    assert(headerTable[id].type == Http::HdrFieldType::ftInt64);    /* must be of an appropriate type */
    assert(number >= 0);
    addEntry(new HttpHeaderEntry(id, NULL, xint64toa(number)));
}

void
HttpHeader::putTime(Http::HdrType id, time_t htime)
{
    assert(any_valid_header(id));
    assert(headerTable[id].type == Http::HdrFieldType::ftDate_1123);    /* must be of an appropriate type */
    assert(htime >= 0);
    addEntry(new HttpHeaderEntry(id, NULL, mkrfc1123(htime)));
}

void
HttpHeader::insertTime(Http::HdrType id, time_t htime)
{
    assert(any_valid_header(id));
    assert(headerTable[id].type == Http::HdrFieldType::ftDate_1123);    /* must be of an appropriate type */
    assert(htime >= 0);
    insertEntry(new HttpHeaderEntry(id, NULL, mkrfc1123(htime)));
}

void
HttpHeader::putStr(Http::HdrType id, const char *str)
{
    assert(any_valid_header(id));
    assert(headerTable[id].type == Http::HdrFieldType::ftStr);  /* must be of an appropriate type */
    assert(str);
    addEntry(new HttpHeaderEntry(id, NULL, str));
}

void
HttpHeader::putAuth(const char *auth_scheme, const char *realm)
{
    assert(auth_scheme && realm);
    httpHeaderPutStrf(this, Http::HdrType::WWW_AUTHENTICATE, "%s realm=\"%s\"", auth_scheme, realm);
}

void
HttpHeader::putCc(const HttpHdrCc * cc)
{
    assert(cc);
    /* remove old directives if any */
    delById(Http::HdrType::CACHE_CONTROL);
    /* pack into mb */
    MemBuf mb;
    mb.init();
    cc->packInto(&mb);
    /* put */
    addEntry(new HttpHeaderEntry(Http::HdrType::CACHE_CONTROL, NULL, mb.buf));
    /* cleanup */
    mb.clean();
}

void
HttpHeader::putContRange(const HttpHdrContRange * cr)
{
    assert(cr);
    /* remove old directives if any */
    delById(Http::HdrType::CONTENT_RANGE);
    /* pack into mb */
    MemBuf mb;
    mb.init();
    httpHdrContRangePackInto(cr, &mb);
    /* put */
    addEntry(new HttpHeaderEntry(Http::HdrType::CONTENT_RANGE, NULL, mb.buf));
    /* cleanup */
    mb.clean();
}

void
HttpHeader::putRange(const HttpHdrRange * range)
{
    assert(range);
    /* remove old directives if any */
    delById(Http::HdrType::RANGE);
    /* pack into mb */
    MemBuf mb;
    mb.init();
    range->packInto(&mb);
    /* put */
    addEntry(new HttpHeaderEntry(Http::HdrType::RANGE, NULL, mb.buf));
    /* cleanup */
    mb.clean();
}

void
HttpHeader::putSc(HttpHdrSc *sc)
{
    assert(sc);
    /* remove old directives if any */
    delById(Http::HdrType::SURROGATE_CONTROL);
    /* pack into mb */
    MemBuf mb;
    mb.init();
    sc->packInto(&mb);
    /* put */
    addEntry(new HttpHeaderEntry(Http::HdrType::SURROGATE_CONTROL, NULL, mb.buf));
    /* cleanup */
    mb.clean();
}

void
HttpHeader::putWarning(const int code, const char *const text)
{
    char buf[512];
    snprintf(buf, sizeof(buf), "%i %s \"%s\"", code, visible_appname_string, text);
    putStr(Http::HdrType::WARNING, buf);
}

/* add extension header (these fields are not parsed/analyzed/joined, etc.) */
void
HttpHeader::putExt(const char *name, const char *value)
{
    assert(name && value);
    debugs(55, 8, this << " adds ext entry " << name << " : " << value);
    addEntry(new HttpHeaderEntry(Http::HdrType::OTHER, name, value));
}

int
HttpHeader::getInt(Http::HdrType id) const
{
    assert(any_valid_header(id));
    assert(headerTable[id].type == Http::HdrFieldType::ftInt);  /* must be of an appropriate type */
    HttpHeaderEntry *e;

    if ((e = findEntry(id)))
        return e->getInt();

    return -1;
}

int64_t
HttpHeader::getInt64(Http::HdrType id) const
{
    assert(any_valid_header(id));
    assert(headerTable[id].type == Http::HdrFieldType::ftInt64);    /* must be of an appropriate type */
    HttpHeaderEntry *e;

    if ((e = findEntry(id)))
        return e->getInt64();

    return -1;
}

time_t
HttpHeader::getTime(Http::HdrType id) const
{
    HttpHeaderEntry *e;
    time_t value = -1;
    assert(any_valid_header(id));
    assert(headerTable[id].type == Http::HdrFieldType::ftDate_1123);    /* must be of an appropriate type */

    if ((e = findEntry(id))) {
        value = parse_rfc1123(e->value.termedBuf());
        httpHeaderNoteParsedEntry(e->id, e->value, value < 0);
    }

    return value;
}

/* sync with httpHeaderGetLastStr */
const char *
HttpHeader::getStr(Http::HdrType id) const
{
    HttpHeaderEntry *e;
    assert(any_valid_header(id));
    assert(headerTable[id].type == Http::HdrFieldType::ftStr);  /* must be of an appropriate type */

    if ((e = findEntry(id))) {
        httpHeaderNoteParsedEntry(e->id, e->value, 0);  /* no errors are possible */
        return e->value.termedBuf();
    }

    return NULL;
}

/* unusual */
const char *
HttpHeader::getLastStr(Http::HdrType id) const
{
    HttpHeaderEntry *e;
    assert(any_valid_header(id));
    assert(headerTable[id].type == Http::HdrFieldType::ftStr);  /* must be of an appropriate type */

    if ((e = findLastEntry(id))) {
        httpHeaderNoteParsedEntry(e->id, e->value, 0);  /* no errors are possible */
        return e->value.termedBuf();
    }

    return NULL;
}

HttpHdrCc *
HttpHeader::getCc() const
{
    if (!CBIT_TEST(mask, Http::HdrType::CACHE_CONTROL))
        return NULL;
    PROF_start(HttpHeader_getCc);

    String s;
    getList(Http::HdrType::CACHE_CONTROL, &s);

    HttpHdrCc *cc=new HttpHdrCc();

    if (!cc->parse(s)) {
        delete cc;
        cc = NULL;
    }

    ++ HttpHeaderStats[owner].ccParsedCount;

    if (cc)
        httpHdrCcUpdateStats(cc, &HttpHeaderStats[owner].ccTypeDistr);

    httpHeaderNoteParsedEntry(Http::HdrType::CACHE_CONTROL, s, !cc);

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

    if ((e = findEntry(Http::HdrType::RANGE)) ||
            (e = findEntry(Http::HdrType::REQUEST_RANGE))) {
        r = HttpHdrRange::ParseCreate(&e->value);
        httpHeaderNoteParsedEntry(e->id, e->value, !r);
    }

    return r;
}

HttpHdrSc *
HttpHeader::getSc() const
{
    if (!CBIT_TEST(mask, Http::HdrType::SURROGATE_CONTROL))
        return NULL;

    String s;

    (void) getList(Http::HdrType::SURROGATE_CONTROL, &s);

    HttpHdrSc *sc = httpHdrScParseCreate(s);

    ++ HttpHeaderStats[owner].ccParsedCount;

    if (sc)
        sc->updateStats(&HttpHeaderStats[owner].scTypeDistr);

    httpHeaderNoteParsedEntry(Http::HdrType::SURROGATE_CONTROL, s, !sc);

    return sc;
}

HttpHdrContRange *
HttpHeader::getContRange() const
{
    HttpHdrContRange *cr = NULL;
    HttpHeaderEntry *e;

    if ((e = findEntry(Http::HdrType::CONTENT_RANGE))) {
        cr = httpHdrContRangeParseCreate(e->value.termedBuf());
        httpHeaderNoteParsedEntry(e->id, e->value, !cr);
    }

    return cr;
}

const char *
HttpHeader::getAuth(Http::HdrType id, const char *auth_scheme) const
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
    struct base64_decode_ctx ctx;
    base64_decode_init(&ctx);
    size_t decodedLen = 0;
    if (!base64_decode_update(&ctx, &decodedLen, reinterpret_cast<uint8_t*>(decodedAuthToken), strlen(field), reinterpret_cast<const uint8_t*>(field)) ||
            !base64_decode_final(&ctx)) {
        return NULL;
    }
    decodedAuthToken[decodedLen] = '\0';
    return decodedAuthToken;
}

ETag
HttpHeader::getETag(Http::HdrType id) const
{
    ETag etag = {NULL, -1};
    HttpHeaderEntry *e;
    assert(headerTable[id].type == Http::HdrFieldType::ftETag);     /* must be of an appropriate type */

    if ((e = findEntry(id)))
        etagParseInit(&etag, e->value.termedBuf());

    return etag;
}

TimeOrTag
HttpHeader::getTimeOrTag(Http::HdrType id) const
{
    TimeOrTag tot;
    HttpHeaderEntry *e;
    assert(headerTable[id].type == Http::HdrFieldType::ftDate_1123_or_ETag);    /* must be of an appropriate type */
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

HttpHeaderEntry::HttpHeaderEntry(Http::HdrType anId, const char *aName, const char *aValue)
{
    assert(any_registered_header(anId));
    id = anId;

    if (id != Http::HdrType::OTHER)
        name = headerTable[id].name;
    else
        name = aName;

    value = aValue;

    if (anId != Http::HdrType::BAD_HDR)
        ++ headerStatsTable[id].aliveCount;

    debugs(55, 9, "created HttpHeaderEntry " << this << ": '" << name << " : " << value );
}

HttpHeaderEntry::~HttpHeaderEntry()
{
    assert(any_valid_header(id));
    debugs(55, 9, "destroying entry " << this << ": '" << name << ": " << value << "'");

    // Http::HdrType::BAD_HDR is filtered out by assert_any_valid_header
    assert(headerStatsTable[id].aliveCount); // is this really needed?
    -- headerStatsTable[id].aliveCount;

    id = Http::HdrType::BAD_HDR;
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
               "NOTICE: Whitespace after header name in '" << getStringPrefix(field_start, field_end-field_start) << "'");

        while (name_len > 0 && xisspace(field_start[name_len - 1]))
            --name_len;

        if (!name_len)
            return NULL;
    }

    /* now we know we can parse it */

    debugs(55, 9, "parsing HttpHeaderEntry: near '" <<  getStringPrefix(field_start, field_end-field_start) << "'");

    /* is it a "known" field? */
    Http::HdrType id = HeaderLookupTable.lookup(SBuf(field_start,name_len));
    debugs(55, 9, "got hdr id hdr: " << id);

    String name;

    String value;

    if (id == Http::HdrType::BAD_HDR)
        id = Http::HdrType::OTHER;

    assert(any_valid_header(id));

    /* set field name */
    if (id == Http::HdrType::OTHER)
        name.limitInit(field_start, name_len);
    else
        name = headerTable[id].name;

    /* trim field value */
    while (value_start < field_end && xisspace(*value_start))
        ++value_start;

    while (value_start < field_end && xisspace(field_end[-1]))
        --field_end;

    if (field_end - value_start > 65534) {
        /* String must be LESS THAN 64K and it adds a terminating NULL */
        debugs(55, DBG_IMPORTANT, "WARNING: ignoring '" << name << "' header of " << (field_end - value_start) << " bytes");

        if (id == Http::HdrType::OTHER)
            name.clean();

        return NULL;
    }

    /* set field value */
    value.limitInit(value_start, field_end - value_start);

    if (id != Http::HdrType::BAD_HDR)
        ++ headerStatsTable[id].seenCount;

    debugs(55, 9, "parsed HttpHeaderEntry: '" << name << ": " << value << "'");

    return new HttpHeaderEntry(id, name.termedBuf(), value.termedBuf());
}

HttpHeaderEntry *
HttpHeaderEntry::clone() const
{
    return new HttpHeaderEntry(id, name.termedBuf(), value.termedBuf());
}

void
HttpHeaderEntry::packInto(Packable * p) const
{
    assert(p);
    p->append(name.rawBuf(), name.size());
    p->append(": ", 2);
    p->append(value.rawBuf(), value.size());
    p->append("\r\n", 2);
}

int
HttpHeaderEntry::getInt() const
{
    assert(any_valid_header(id));
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
    assert(any_valid_header(id));
    int64_t val = -1;
    int ok = httpHeaderParseOffset(value.termedBuf(), &val);
    httpHeaderNoteParsedEntry(id, value, !ok);
    /* XXX: Should we check ok - ie
     * return ok ? -1 : value;
     */
    return val;
}

static void
httpHeaderNoteParsedEntry(Http::HdrType id, String const &context, int error)
{
    if (id != Http::HdrType::BAD_HDR)
        ++ headerStatsTable[id].parsCount;

    if (error) {
        if (id != Http::HdrType::BAD_HDR)
            ++ headerStatsTable[id].errCount;
        debugs(55, 2, "cannot parse hdr field: '" << headerTable[id].name << ": " << context << "'");
    }
}

/*
 * Reports
 */

/* tmp variable used to pass stat info to dumpers */
extern const HttpHeaderStat *dump_stat;     /* argh! */
const HttpHeaderStat *dump_stat = NULL;

void
httpHeaderFieldStatDumper(StoreEntry * sentry, int, double val, double, int count)
{
    const int id = (int) val;
    const int valid_id = id < Http::HdrType::ENUM_END;
    const char *name = valid_id ? headerTable[id].name : "INVALID";
    int visible = count > 0;
    /* for entries with zero count, list only those that belong to current type of message */

    if (!visible && valid_id && dump_stat->owner_mask)
        visible = CBIT_TEST(*dump_stat->owner_mask, id);

    if (visible)
        storeAppendPrintf(sentry, "%2d\t %-20s\t %5d\t %6.2f\n",
                          id, name, count, xdiv(count, dump_stat->busyDestroyedCount));
}

static void
httpHeaderFldsPerHdrDumper(StoreEntry * sentry, int idx, double val, double, int count)
{
    if (count)
        storeAppendPrintf(sentry, "%2d\t %5d\t %5d\t %6.2f\n",
                          idx, (int) val, count,
                          xpercent(count, dump_stat->destroyedCount));
}

static void
httpHeaderStatDump(const HttpHeaderStat * hs, StoreEntry * e)
{
    assert(hs);
    assert(e);

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

    // scan heaaderTable and output
    for (int j = 0; headerTable[j].name != nullptr; ++j) {
        auto stats = headerStatsTable[j];
        storeAppendPrintf(e, "%2d\t %-25s\t %5d\t %6.3f\t %6.3f\n",
                          headerTable[j].id, headerTable[j].name, stats.aliveCount,
                          xpercent(stats.errCount, stats.parsCount),
                          xpercent(stats.repCount, stats.seenCount));
    }

    storeAppendPrintf(e, "Headers Parsed: %d + %d = %d\n",
                      HttpHeaderStats[hoRequest].parsedCount,
                      HttpHeaderStats[hoReply].parsedCount,
                      HttpHeaderStats[0].parsedCount);
    storeAppendPrintf(e, "Hdr Fields Parsed: %d\n", HeaderEntryParsedCount);
}

int
HttpHeader::hasListMember(Http::HdrType id, const char *member, const char separator) const
{
    int result = 0;
    const char *pos = NULL;
    const char *item;
    int ilen;
    int mlen = strlen(member);

    assert(any_valid_header(id));

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
        Http::HdrType id = e->id;
        if (CBIT_TEST(HopByHopHeadersMask, id)) {
            delAt(pos, headers_deleted);
            CBIT_CLR(mask, id);
        }
    }
}

void
HttpHeader::removeConnectionHeaderEntries()
{
    if (has(Http::HdrType::CONNECTION)) {
        /* anything that matches Connection list member will be deleted */
        String strConnection;

        (void) getList(Http::HdrType::CONNECTION, &strConnection);
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

