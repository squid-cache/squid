/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 68    HTTP Content-Range Header */

#include "squid.h"
#include "base/Packable.h"
#include "Debug.h"
#include "enums.h"
#include "HttpHdrContRange.h"
#include "HttpHeaderTools.h"

/*
 *    Currently only byte ranges are supported
 *
 *    Content-Range = "Content-Range" ":" content-range-spec
 *    content-range-spec      = byte-content-range-spec
 *    byte-content-range-spec = bytes-unit SP
 *                              ( byte-range-resp-spec | "*") "/"
 *                              ( entity-length | "*" )
 *    byte-range-resp-spec = first-byte-pos "-" last-byte-pos
 *    entity-length        = 1*DIGIT
 */

/* local constants */
#define range_spec_unknown (-1)

/* local routines */
#define known_spec(s) ((s) != range_spec_unknown)
#define size_min(a,b) ((a) <= (b) ? (a) : (b))
#define size_diff(a,b) ((a) >= (b) ? ((a)-(b)) : 0)

/* globals */

/* parses range-resp-spec and inits spec, returns true on success */
static int
httpHdrRangeRespSpecParseInit(HttpHdrRangeSpec * spec, const char *field, int flen)
{
    const char *p;
    assert(spec);
    spec->offset = spec->length = range_spec_unknown;

    if (flen < 2)
        return 0;

    /* is spec given ? */
    if (*field == '*')
        return 1;

    /* check format, must be %d-%d */
    if (!((p = strchr(field, '-')) && (p - field < flen))) {
        debugs(68, 2, "invalid (no '-') resp-range-spec near: '" << field << "'");
        return 0;
    }

    /* parse offset */
    if (!httpHeaderParseOffset(field, &spec->offset))
        return 0;

    /* Additional check for BUG2155 - there MUST BE first-byte-pos and it MUST be positive*/
    if (spec->offset < 0) {
        debugs(68, 2, "invalid (no first-byte-pos or it is negative) resp-range-spec near: '" << field << "'");
        return 0;
    }

    ++p;

    /* do we have last-pos ? */
    if (p - field >= flen) {
        debugs(68, 2, "invalid (no last-byte-pos) resp-range-spec near: '" << field << "'");
        return 0;
    }

    int64_t last_pos;

    if (!httpHeaderParseOffset(p, &last_pos))
        return 0;

    if (last_pos < spec->offset) {
        debugs(68, 2, "invalid (negative last-byte-pos) resp-range-spec near: '" << field << "'");
        return 0;
    }

    spec->length = size_diff(last_pos + 1, spec->offset);

    /* we managed to parse, check if the result makes sence */
    if (spec->length <= 0) {
        debugs(68, 2, "invalid range (" << spec->offset << " += " <<
               (long int) spec->length << ") in resp-range-spec near: '" << field << "'");
        return 0;
    }

    return 1;
}

static void
httpHdrRangeRespSpecPackInto(const HttpHdrRangeSpec * spec, Packable * p)
{
    /* Ensure typecast is safe */
    assert (spec->length >= 0);

    if (!known_spec(spec->offset) || !known_spec(spec->length))
        p->append("*", 1);
    else
        p->appendf("bytes %" PRId64 "-%" PRId64, spec->offset, spec->offset + spec->length - 1);
}

/*
 * Content Range
 */

HttpHdrContRange *
httpHdrContRangeCreate(void)
{
    HttpHdrContRange *r = new HttpHdrContRange;
    r->spec.offset = r->spec.length = range_spec_unknown;
    r->elength = range_spec_unknown;
    return r;
}

HttpHdrContRange *
httpHdrContRangeParseCreate(const char *str)
{
    HttpHdrContRange *r = httpHdrContRangeCreate();

    if (!httpHdrContRangeParseInit(r, str)) {
        delete r;
        return nullptr;
    }

    return r;
}

/* returns true if ranges are valid; inits HttpHdrContRange */
int
httpHdrContRangeParseInit(HttpHdrContRange * range, const char *str)
{
    const char *p;
    assert(range && str);
    debugs(68, 8, "parsing content-range field: '" << str << "'");
    /* check range type */

    if (strncasecmp(str, "bytes ", 6))
        return 0;

    str += 6;

    /* split */
    if (!(p = strchr(str, '/')))
        return 0;

    if (*str == '*')
        range->spec.offset = range->spec.length = range_spec_unknown;
    else if (!httpHdrRangeRespSpecParseInit(&range->spec, str, p - str))
        return 0;

    ++p;

    if (*p == '*') {
        if (!known_spec(range->spec.offset)) {
            debugs(68, 2, "invalid (*/*) content-range-spec near: '" << str << "'");
            return 0;
        }
        range->elength = range_spec_unknown;
    } else if (!httpHeaderParseOffset(p, &range->elength))
        return 0;
    else if (range->elength <= 0) {
        /* Additional paranoidal check for BUG2155 - entity-length MUST be > 0 */
        debugs(68, 2, "invalid (entity-length is negative) content-range-spec near: '" << str << "'");
        return 0;
    } else if (known_spec(range->spec.length) && range->elength < (range->spec.offset + range->spec.length)) {
        debugs(68, 2, "invalid (range is outside entity-length) content-range-spec near: '" << str << "'");
        return 0;
    }

    // reject unsatisfied-range and such; we only use well-defined ranges today
    if (!known_spec(range->spec.offset) || !known_spec(range->spec.length)) {
        debugs(68, 2, "unwanted content-range-spec near: '" << str << "'");
        return 0;
    }

    debugs(68, 8, "parsed content-range field: " <<
           (long int) range->spec.offset << "-" <<
           (long int) range->spec.offset + range->spec.length - 1 << " / " <<
           (long int) range->elength);

    return 1;
}

HttpHdrContRange *
httpHdrContRangeDup(const HttpHdrContRange * range)
{
    HttpHdrContRange *dup;
    assert(range);
    dup = httpHdrContRangeCreate();
    *dup = *range;
    return dup;
}

void
httpHdrContRangePackInto(const HttpHdrContRange * range, Packable * p)
{
    assert(range && p);
    httpHdrRangeRespSpecPackInto(&range->spec, p);
    /* Ensure typecast is safe */
    assert (range->elength >= 0);

    if (!known_spec(range->elength))
        p->append("/*", 2);
    else
        p->appendf("/%" PRId64, range->elength);
}

void
httpHdrContRangeSet(HttpHdrContRange * cr, HttpHdrRangeSpec spec, int64_t ent_len)
{
    assert(cr && ent_len >= 0);
    cr->spec = spec;
    cr->elength = ent_len;
}

