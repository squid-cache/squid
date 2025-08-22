/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 66    HTTP Header Tools */

#include "squid.h"
#include "compat/strtoll.h"
#include "http/HeaderTools.h"
#include "HttpHdrContRange.h"
#include "HttpHeader.h"
#include "MemBuf.h"
#include "StrList.h"

#include <cerrno>

static void httpHeaderPutStrvf(HttpHeader * hdr, Http::HdrType id, const char *fmt, va_list vargs);

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
httpHeaderHasConnDir(const HttpHeader * hdr, const SBuf &directive)
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
 * parses an int field, complains if something went wrong, returns true on
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

