/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 66    HTTP Header Tools */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "base/EnumIterator.h"
#include "client_side.h"
#include "client_side_request.h"
#include "comm/Connection.h"
#include "compat/strtoll.h"
#include "ConfigParser.h"
#include "fde.h"
#include "globals.h"
#include "http/RegisteredHeaders.h"
#include "http/Stream.h"
#include "HttpHdrContRange.h"
#include "HttpHeader.h"
#include "HttpHeaderFieldInfo.h"
#include "HttpHeaderTools.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "SquidConfig.h"
#include "Store.h"
#include "StrList.h"

#if USE_OPENSSL
#include "ssl/support.h"
#endif

#include <algorithm>
#include <cerrno>
#include <string>

static void httpHeaderPutStrvf(HttpHeader * hdr, Http::HdrType id, const char *fmt, va_list vargs);
static void httpHdrAdd(HttpHeader *heads, HttpRequest *request, const AccessLogEntryPointer &al, HeaderWithAclList &headersAdd);

void
httpHeaderMaskInit(HttpHeaderMask * mask, int value)
{
    memset(mask, value, sizeof(*mask));
}

/* same as httpHeaderPutStr, but formats the string using snprintf first */
void
httpHeaderPutStrf(HttpHeader * hdr, Http::HdrType id, const char *fmt,...)
{
    va_list args;
    va_start(args, fmt);

    httpHeaderPutStrvf(hdr, id, fmt, args);
    va_end(args);
}

/* used by httpHeaderPutStrf */
static void
httpHeaderPutStrvf(HttpHeader * hdr, Http::HdrType id, const char *fmt, va_list vargs)
{
    MemBuf mb;
    mb.init();
    mb.vappendf(fmt, vargs);
    hdr->putStr(id, mb.buf);
    mb.clean();
}

/** wrapper arrounf PutContRange */
void
httpHeaderAddContRange(HttpHeader * hdr, HttpHdrRangeSpec spec, int64_t ent_len)
{
    HttpHdrContRange *cr = httpHdrContRangeCreate();
    assert(hdr && ent_len >= 0);
    httpHdrContRangeSet(cr, spec, ent_len);
    hdr->putContRange(cr);
    delete cr;
}

/**
 * \return true if a given directive is found in the Connection header field-value.
 *
 * \note if no Connection header exists we may check the Proxy-Connection header
 */
bool
httpHeaderHasConnDir(const HttpHeader * hdr, const char *directive)
{
    String list;

    /* what type of header do we have? */
    if (hdr->getList(Http::HdrType::CONNECTION, &list))
        return strListIsMember(&list, directive, ',') != 0;

#if USE_HTTP_VIOLATIONS
    if (hdr->getList(Http::HdrType::PROXY_CONNECTION, &list))
        return strListIsMember(&list, directive, ',') != 0;
#endif

    // else, no connection header for it to exist in
    return false;
}

/** handy to printf prefixes of potentially very long buffers */
const char *
getStringPrefix(const char *str, size_t sz)
{
#define SHORT_PREFIX_SIZE 512
    LOCAL_ARRAY(char, buf, SHORT_PREFIX_SIZE);
    xstrncpy(buf, str, (sz+1 > SHORT_PREFIX_SIZE) ? SHORT_PREFIX_SIZE : sz);
    return buf;
}

/**
 * parses an int field, complains if soemthing went wrong, returns true on
 * success
 */
int
httpHeaderParseInt(const char *start, int *value)
{
    assert(value);
    *value = atoi(start);

    if (!*value && !xisdigit(*start)) {
        debugs(66, 2, "failed to parse an int header field near '" << start << "'");
        return 0;
    }

    return 1;
}

bool
httpHeaderParseOffset(const char *start, int64_t *value, char **endPtr)
{
    char *end = nullptr;
    errno = 0;
    const int64_t res = strtoll(start, &end, 10);
    if (errno && !res) {
        debugs(66, 7, "failed to parse malformed offset in " << start);
        return false;
    }
    if (errno == ERANGE && (res == LLONG_MIN || res == LLONG_MAX)) { // no overflow
        debugs(66, 7, "failed to parse huge offset in " << start);
        return false;
    }
    if (start == end) {
        debugs(66, 7, "failed to parse empty offset");
        return false;
    }
    *value = res;
    if (endPtr)
        *endPtr = end;
    debugs(66, 7, "offset " << start << " parsed as " << res);
    return true;
}

/**
 * Parses a quoted-string field (RFC 2616 section 2.2), complains if
 * something went wrong, returns non-zero on success.
 * Un-escapes quoted-pair characters found within the string.
 * start should point at the first double-quote.
 */
int
httpHeaderParseQuotedString(const char *start, const int len, String *val)
{
    const char *end, *pos;
    val->clean();
    if (*start != '"') {
        debugs(66, 2, HERE << "failed to parse a quoted-string header field near '" << start << "'");
        return 0;
    }
    pos = start + 1;

    while (*pos != '"' && len > (pos-start)) {

        if (*pos =='\r') {
            ++pos;
            if ((pos-start) > len || *pos != '\n') {
                debugs(66, 2, HERE << "failed to parse a quoted-string header field with '\\r' octet " << (start-pos)
                       << " bytes into '" << start << "'");
                val->clean();
                return 0;
            }
        }

        if (*pos == '\n') {
            ++pos;
            if ( (pos-start) > len || (*pos != ' ' && *pos != '\t')) {
                debugs(66, 2, HERE << "failed to parse multiline quoted-string header field '" << start << "'");
                val->clean();
                return 0;
            }
            // TODO: replace the entire LWS with a space
            val->append(" ");
            ++pos;
            debugs(66, 2, HERE << "len < pos-start => " << len << " < " << (pos-start));
            continue;
        }

        bool quoted = (*pos == '\\');
        if (quoted) {
            ++pos;
            if (!*pos || (pos-start) > len) {
                debugs(66, 2, HERE << "failed to parse a quoted-string header field near '" << start << "'");
                val->clean();
                return 0;
            }
        }
        end = pos;
        while (end < (start+len) && *end != '\\' && *end != '\"' && (unsigned char)*end > 0x1F && *end != 0x7F)
            ++end;
        if (((unsigned char)*end <= 0x1F && *end != '\r' && *end != '\n') || *end == 0x7F) {
            debugs(66, 2, HERE << "failed to parse a quoted-string header field with CTL octet " << (start-pos)
                   << " bytes into '" << start << "'");
            val->clean();
            return 0;
        }
        val->append(pos, end-pos);
        pos = end;
    }

    if (*pos != '\"') {
        debugs(66, 2, HERE << "failed to parse a quoted-string header field which did not end with \" ");
        val->clean();
        return 0;
    }
    /* Make sure it's defined even if empty "" */
    if (!val->termedBuf())
        val->limitInit("", 0);
    return 1;
}

SBuf
httpHeaderQuoteString(const char *raw)
{
    assert(raw);

    // TODO: Optimize by appending a sequence of characters instead of a char.
    // This optimization may be easier with Tokenizer after raw becomes SBuf.

    // RFC 7230 says a "sender SHOULD NOT generate a quoted-pair in a
    // quoted-string except where necessary" (i.e., DQUOTE and backslash)
    bool needInnerQuote = false;
    for (const char *s = raw; !needInnerQuote &&  *s; ++s)
        needInnerQuote = *s == '"' || *s == '\\';

    SBuf quotedStr;
    quotedStr.append('"');

    if (needInnerQuote) {
        for (const char *s = raw; *s; ++s) {
            if (*s == '"' || *s == '\\')
                quotedStr.append('\\');
            quotedStr.append(*s);
        }
    } else {
        quotedStr.append(raw);
    }

    quotedStr.append('"');
    return quotedStr;
}

/**
 * Checks the anonymizer (header_access) configuration.
 *
 * \retval 0    Header is explicitly blocked for removal
 * \retval 1    Header is explicitly allowed
 * \retval 1    Header has been replaced, the current version can be used.
 * \retval 1    Header has no access controls to test
 */
static int
httpHdrMangle(HttpHeaderEntry * e, HttpRequest * request, HeaderManglers *hms)
{
    int retval;

    assert(e);

    const headerMangler *hm = hms->find(*e);

    /* mangler or checklist went away. default allow */
    if (!hm || !hm->access_list) {
        debugs(66, 7, "couldn't find mangler or access list. Allowing");
        return 1;
    }

    ACLFilledChecklist checklist(hm->access_list, request, NULL);

    if (checklist.fastCheck() == ACCESS_ALLOWED) {
        /* aclCheckFast returns true for allow. */
        debugs(66, 7, "checklist for mangler is positive. Mangle");
        retval = 1;
    } else if (NULL == hm->replacement) {
        /* It was denied, and we don't have any replacement */
        debugs(66, 7, "checklist denied, we have no replacement. Pass");
        retval = 0;
    } else {
        /* It was denied, but we have a replacement. Replace the
         * header on the fly, and return that the new header
         * is allowed.
         */
        debugs(66, 7, "checklist denied but we have replacement. Replace");
        e->value = hm->replacement;
        retval = 1;
    }

    return retval;
}

/** Mangles headers for a list of headers. */
void
httpHdrMangleList(HttpHeader *l, HttpRequest *request, const AccessLogEntryPointer &al, req_or_rep_t req_or_rep)
{
    HttpHeaderEntry *e;
    HttpHeaderPos p = HttpHeaderInitPos;

    /* check with anonymizer tables */
    HeaderManglers *hms = nullptr;
    HeaderWithAclList *headersAdd = nullptr;

    switch (req_or_rep) {
    case ROR_REQUEST:
        hms = Config.request_header_access;
        headersAdd = Config.request_header_add;
        break;
    case ROR_REPLY:
        hms = Config.reply_header_access;
        headersAdd = Config.reply_header_add;
        break;
    }

    if (hms) {
        int headers_deleted = 0;
        while ((e = l->getEntry(&p))) {
            if (0 == httpHdrMangle(e, request, hms))
                l->delAt(p, headers_deleted);
        }

        if (headers_deleted)
            l->refreshMask();
    }

    if (headersAdd && !headersAdd->empty()) {
        httpHdrAdd(l, request, al, *headersAdd);
    }
}

static
void header_mangler_clean(headerMangler &m)
{
    aclDestroyAccessList(&m.access_list);
    safe_free(m.replacement);
}

static
void header_mangler_dump_access(StoreEntry * entry, const char *option,
                                const headerMangler &m, const char *name)
{
    if (m.access_list != NULL) {
        storeAppendPrintf(entry, "%s ", option);
        dump_acl_access(entry, name, m.access_list);
    }
}

static
void header_mangler_dump_replacement(StoreEntry * entry, const char *option,
                                     const headerMangler &m, const char *name)
{
    if (m.replacement)
        storeAppendPrintf(entry, "%s %s %s\n", option, name, m.replacement);
}

HeaderManglers::HeaderManglers()
{
    memset(known, 0, sizeof(known));
    memset(&all, 0, sizeof(all));
}

HeaderManglers::~HeaderManglers()
{
    for (auto i : WholeEnum<Http::HdrType>())
        header_mangler_clean(known[i]);

    for (auto i : custom)
        header_mangler_clean(i.second);

    header_mangler_clean(all);
}

void
HeaderManglers::dumpAccess(StoreEntry * entry, const char *name) const
{
    for (auto id : WholeEnum<Http::HdrType>())
        header_mangler_dump_access(entry, name, known[id], Http::HeaderLookupTable.lookup(id).name);

    for (auto i : custom)
        header_mangler_dump_access(entry, name, i.second, i.first.c_str());

    header_mangler_dump_access(entry, name, all, "All");
}

void
HeaderManglers::dumpReplacement(StoreEntry * entry, const char *name) const
{
    for (auto id : WholeEnum<Http::HdrType>()) {
        header_mangler_dump_replacement(entry, name, known[id], Http::HeaderLookupTable.lookup(id).name);
    }

    for (auto i: custom) {
        header_mangler_dump_replacement(entry, name, i.second, i.first.c_str());
    }

    header_mangler_dump_replacement(entry, name, all, "All");
}

headerMangler *
HeaderManglers::track(const char *name)
{
    if (strcmp(name, "All") == 0)
        return &all;

    const Http::HdrType id = Http::HeaderLookupTable.lookup(SBuf(name)).id;

    if (id != Http::HdrType::BAD_HDR)
        return &known[id];

    if (strcmp(name, "Other") == 0)
        return &known[Http::HdrType::OTHER];

    return &custom[name];
}

void
HeaderManglers::setReplacement(const char *name, const char *value)
{
    // for backword compatibility, we allow replacements to be configured
    // for headers w/o access rules, but such replacements are ignored
    headerMangler *m = track(name);

    safe_free(m->replacement); // overwrite old value if any
    m->replacement = xstrdup(value);
}

const headerMangler *
HeaderManglers::find(const HttpHeaderEntry &e) const
{
    // a known header with a configured ACL list
    if (e.id != Http::HdrType::OTHER && Http::any_HdrType_enum_value(e.id) &&
            known[e.id].access_list)
        return &known[e.id];

    // a custom header
    if (e.id == Http::HdrType::OTHER) {
        // does it have an ACL list configured?
        // Optimize: use a name type that we do not need to convert to here
        const ManglersByName::const_iterator i = custom.find(e.name.termedBuf());
        if (i != custom.end())
            return &i->second;
    }

    // Next-to-last resort: "Other" rules match any custom header
    if (e.id == Http::HdrType::OTHER && known[Http::HdrType::OTHER].access_list)
        return &known[Http::HdrType::OTHER];

    // Last resort: "All" rules match any header
    if (all.access_list)
        return &all;

    return NULL;
}

void
httpHdrAdd(HttpHeader *heads, HttpRequest *request, const AccessLogEntryPointer &al, HeaderWithAclList &headersAdd)
{
    ACLFilledChecklist checklist(NULL, request, NULL);

    for (HeaderWithAclList::const_iterator hwa = headersAdd.begin(); hwa != headersAdd.end(); ++hwa) {
        if (!hwa->aclList || checklist.fastCheck(hwa->aclList) == ACCESS_ALLOWED) {
            const char *fieldValue = NULL;
            MemBuf mb;
            if (hwa->quoted) {
                if (al != NULL) {
                    mb.init();
                    hwa->valueFormat->assemble(mb, al, 0);
                    fieldValue = mb.content();
                }
            } else {
                fieldValue = hwa->fieldValue.c_str();
            }

            if (!fieldValue || fieldValue[0] == '\0')
                fieldValue = "-";

            HttpHeaderEntry *e = new HttpHeaderEntry(hwa->fieldId, hwa->fieldName.c_str(),
                    fieldValue);
            heads->addEntry(e);
        }
    }
}

