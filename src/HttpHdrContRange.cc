
/*
 * $Id: HttpHdrContRange.cc,v 1.22 2007/08/13 18:25:14 hno Exp $
 *
 * DEBUG: section 68    HTTP Content-Range Header
 * AUTHOR: Alex Rousskov
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
#include "HttpHdrContRange.h"

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

    p++;

    /* do we have last-pos ? */
    if (p - field < flen) {
        int64_t last_pos;

        if (!httpHeaderParseOffset(p, &last_pos))
            return 0;

        spec->length = size_diff(last_pos + 1, spec->offset);
    }

    /* Ensure typecast is safe */
    assert (spec->length >= 0);

    /* we managed to parse, check if the result makes sence */
    if (known_spec(spec->length) && spec->length == 0) {
        debugs(68, 2, "invalid range (" << spec->offset << " += " <<
               (long int) spec->length << ") in resp-range-spec near: '" << field << "'");
        return 0;
    }

    return 1;
}

static void
httpHdrRangeRespSpecPackInto(const HttpHdrRangeSpec * spec, Packer * p)
{
    /* Ensure typecast is safe */
    assert (spec->length >= 0);

    if (!known_spec(spec->offset) || !known_spec(spec->length))
        packerPrintf(p, "*");
    else
        packerPrintf(p, "bytes %"PRId64"-%"PRId64,
                     spec->offset, spec->offset + spec->length - 1);
}

/*
 * Content Range
 */

HttpHdrContRange *
httpHdrContRangeCreate(void)
{
    HttpHdrContRange *r = (HttpHdrContRange *)memAllocate(MEM_HTTP_HDR_CONTENT_RANGE);
    r->spec.offset = r->spec.length = range_spec_unknown;
    r->elength = range_spec_unknown;
    return r;
}

HttpHdrContRange *
httpHdrContRangeParseCreate(const char *str)
{
    HttpHdrContRange *r = httpHdrContRangeCreate();

    if (!httpHdrContRangeParseInit(r, str)) {
        httpHdrContRangeDestroy(r);
        r = NULL;
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

    p++;

    if (*p == '*')
        range->elength = range_spec_unknown;
    else if (!httpHeaderParseOffset(p, &range->elength))
        return 0;

        debugs(68, 8, "parsed content-range field: " <<
               (long int) range->spec.offset << "-" <<
               (long int) range->spec.offset + range->spec.length - 1 << " / " <<
               (long int) range->elength);

    return 1;
}

void
httpHdrContRangeDestroy(HttpHdrContRange * range)
{
    assert(range);
    memFree(range, MEM_HTTP_HDR_CONTENT_RANGE);
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
httpHdrContRangePackInto(const HttpHdrContRange * range, Packer * p)
{
    assert(range && p);
    httpHdrRangeRespSpecPackInto(&range->spec, p);
    /* Ensure typecast is safe */
    assert (range->elength >= 0);

    if (!known_spec(range->elength))
        packerPrintf(p, "/*");
    else
        packerPrintf(p, "/%"PRId64, range->elength);
}

void
httpHdrContRangeSet(HttpHdrContRange * cr, HttpHdrRangeSpec spec, int64_t ent_len)
{
    assert(cr && ent_len >= 0);
    cr->spec = spec;
    cr->elength = ent_len;
}
