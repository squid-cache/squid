
/*
 * $Id: HttpHdrRange.cc,v 1.7 1998/05/11 18:44:25 rousskov Exp $
 *
 * DEBUG: section 64    HTTP Range Header
 * AUTHOR: Alex Rousskov
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"

/*
 *    Currently only byte ranges are supported
 *
 *    Essentially, there are three types of byte ranges:
 *
 *      1) first-byte-pos "-" last-byte-pos  // range
 *      2) first-byte-pos "-"                // trailer
 *      3)                "-" suffix-length  // suffix (last length bytes)
 *
 *
 *    When Range field is parsed, we have no clue about the content
 *    length of the document. Thus, we simply code an "absent" part
 *    using range_spec_unknown constant.
 *
 *    Note: when response length becomes known, we convert any range
 *    spec into type one above. (Canonization process).
 */


/* local constants */
#define range_spec_unknown ((size_t)-1)

/* local routines */
#define known_spec(s) ((s) != range_spec_unknown)
#define size_min(a,b) ((a) <= (b) ? (a) : (b))
#define size_diff(a,b) ((a) >= (b) ? ((a)-(b)) : 0)
static HttpHdrRangeSpec *httpHdrRangeSpecDup(const HttpHdrRangeSpec * spec);
static int httpHdrRangeSpecCanonize(HttpHdrRangeSpec * spec, size_t clen);
static void httpHdrRangeSpecPackInto(const HttpHdrRangeSpec * spec, Packer * p);

/* globals */
static int RangeParsedCount = 0;

/*
 * Range-Spec
 */

static HttpHdrRangeSpec *
httpHdrRangeSpecCreate()
{
    return memAllocate(MEM_HTTP_HDR_RANGE_SPEC);
}

/* parses range-spec and returns new object on success */
static HttpHdrRangeSpec *
httpHdrRangeSpecParseCreate(const char *field, int flen)
{
    HttpHdrRangeSpec spec =
    {range_spec_unknown, range_spec_unknown};
    const char *p;
    if (flen < 2)
	return NULL;
    /* is it a suffix-byte-range-spec ? */
    if (*field == '-') {
	if (!httpHeaderParseSize(field + 1, &spec.length))
	    return NULL;
    } else
	/* must have a '-' somewhere in _this_ field */
    if (!((p = strchr(field, '-')) || (p - field >= flen))) {
	debug(64, 2) ("ignoring invalid (missing '-') range-spec near: '%s'\n", field);
	return NULL;
    } else {
	if (!httpHeaderParseSize(field, &spec.offset))
	    return NULL;
	p++;
	/* do we have last-pos ? */
	if (p - field < flen) {
	    size_t last_pos;
	    if (!httpHeaderParseSize(p, &last_pos))
		return NULL;
	    spec.length = size_diff(last_pos + 1, spec.offset);
	}
    }
    /* we managed to parse, check if the result makes sence */
    if (known_spec(spec.length) && !spec.length) {
	debug(64, 2) ("ignoring invalid (zero length) range-spec near: '%s'\n", field);
	return NULL;
    }
    return httpHdrRangeSpecDup(&spec);
}

static void
httpHdrRangeSpecDestroy(HttpHdrRangeSpec * spec)
{
    memFree(MEM_HTTP_HDR_RANGE_SPEC, spec);
}


static HttpHdrRangeSpec *
httpHdrRangeSpecDup(const HttpHdrRangeSpec * spec)
{
    HttpHdrRangeSpec *dup = httpHdrRangeSpecCreate();
    dup->offset = spec->offset;
    dup->length = spec->length;
    return dup;
}

static void
httpHdrRangeSpecPackInto(const HttpHdrRangeSpec * spec, Packer * p)
{
    if (!known_spec(spec->offset))	/* suffix */
	packerPrintf(p, "-%d", spec->length);
    else if (!known_spec(spec->length))		/* trailer */
	packerPrintf(p, "%d-", spec->offset);
    else			/* range */
	packerPrintf(p, "%d-%d",
	    spec->offset, spec->offset + spec->length - 1);
}

/* fills "absent" positions in range specification based on response body size 
 * returns true if the range is still valid
 * range is valid if its intersection with [0,length-1] is not empty
 */
static int
httpHdrRangeSpecCanonize(HttpHdrRangeSpec * spec, size_t clen)
{
    if (!known_spec(spec->offset))	/* suffix */
	spec->offset = size_diff(clen, spec->length);
    else if (!known_spec(spec->length))		/* trailer */
	spec->length = size_diff(clen, spec->offset);
    /* we have a "range" now, adjust length if needed */
    assert(known_spec(spec->length));
    assert(known_spec(spec->offset));
    spec->length = size_min(size_diff(clen, spec->offset), spec->length);
    /* check range validity */
    return spec->length > 0;
}

/*
 * Range
 */

HttpHdrRange *
httpHdrRangeCreate()
{
    HttpHdrRange *r = memAllocate(MEM_HTTP_HDR_RANGE);
    stackInit(&r->specs);
    return r;
}

HttpHdrRange *
httpHdrRangeParseCreate(const String *str)
{
    HttpHdrRange *r = httpHdrRangeCreate();
    if (!httpHdrRangeParseInit(r, str)) {
	httpHdrRangeDestroy(r);
	r = NULL;
    }
    return r;
}

/* returns true if ranges are valid; inits HttpHdrRange */
int
httpHdrRangeParseInit(HttpHdrRange * range, const String *str)
{
    const char *item;
    const char *pos = NULL;
    int ilen;
    int count = 0;
    assert(range && str);
    RangeParsedCount++;
    debug(64, 8) ("parsing range field: '%s'\n", strBuf(*str));
    /* check range type */
    if (strNCaseCmp(*str, "bytes=", 6))
	return 0;
    /* skip "bytes="; hack! */
    pos = strBuf(*str)+5;
    /* iterate through comma separated list */
    while (strListGetItem(str, ',', &item, &ilen, &pos)) {
	HttpHdrRangeSpec *spec = httpHdrRangeSpecParseCreate(item, ilen);
	/*
	 * HTTP/1.1 draft says we must ignore the whole header field if one spec
	 * is invalid. However, RFC 2068 just says that we must ignore that spec.
	 */
	if (spec)
	    stackPush(&range->specs, spec);
	count++;
    }
    debug(68, 8) ("parsed range range count: %d\n", range->specs.count);
    return range->specs.count;
}

void
httpHdrRangeDestroy(HttpHdrRange * range)
{
    assert(range);
    while (range->specs.count)
	httpHdrRangeSpecDestroy(stackPop(&range->specs));
    stackClean(&range->specs);
    memFree(MEM_HTTP_HDR_RANGE, range);
}

HttpHdrRange *
httpHdrRangeDup(const HttpHdrRange * range)
{
    HttpHdrRange *dup;
    int i;
    assert(range);
    dup = httpHdrRangeCreate();
    stackPrePush(&dup->specs, range->specs.count);
    for (i = 0; i < range->specs.count; i++)
	stackPush(&dup->specs, httpHdrRangeSpecDup(range->specs.items[i]));
    assert(range->specs.count == dup->specs.count);
    return dup;
}

void
httpHdrRangePackInto(const HttpHdrRange * range, Packer * p)
{
    HttpHdrRangePos pos = HttpHdrRangeInitPos;
    HttpHdrRangeSpec spec;
    assert(range);
    while (httpHdrRangeGetSpec(range, &spec, &pos)) {
	if (pos != HttpHdrRangeInitPos)
	    packerAppend(p, ",", 1);
	httpHdrRangeSpecPackInto(&spec, p);
    }
}

/*
 * canonizes all range specs within a set preserving the order
 * returns true if the set is valid after canonization; 
 * the set is valid if 
 *   - all range specs are valid and 
 *   - there is at least one range spec
 */
int
httpHdrRangeCanonize(HttpHdrRange * range, size_t clen)
{
    int i;
    assert(range);
    for (i = 0; i < range->specs.count; i++)
	if (!httpHdrRangeSpecCanonize(range->specs.items[i], clen))
	    return 0;
    return range->specs.count;
}

/* searches for next range, returns true if found */
int
httpHdrRangeGetSpec(const HttpHdrRange * range, HttpHdrRangeSpec * spec, int *pos)
{
    assert(range && spec);
    assert(pos && *pos >= -1 && *pos < range->specs.count);
    (*pos)++;
    if (*pos < range->specs.count) {
	*spec = *(HttpHdrRangeSpec *) range->specs.items[*pos];
	return 1;
    }
    spec->offset = spec->length = 0;
    return 0;
}
