
/*
 * $Id: HttpHdrRange.cc,v 1.26 2001/10/24 08:19:07 hno Exp $
 *
 * DEBUG: section 64    HTTP Range Header
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
#define range_spec_unknown ((ssize_t)-1)

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
httpHdrRangeSpecCreate(void)
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
	    ssize_t last_pos;
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
    memFree(spec, MEM_HTTP_HDR_RANGE_SPEC);
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
	packerPrintf(p, "-%ld", (long int) spec->length);
    else if (!known_spec(spec->length))		/* trailer */
	packerPrintf(p, "%ld-", (long int) spec->offset);
    else			/* range */
	packerPrintf(p, "%ld-%ld",
	    (long int) spec->offset, (long int) spec->offset + spec->length - 1);
}

/* fills "absent" positions in range specification based on response body size 
 * returns true if the range is still valid
 * range is valid if its intersection with [0,length-1] is not empty
 */
static int
httpHdrRangeSpecCanonize(HttpHdrRangeSpec * spec, size_t clen)
{
    debug(64, 5) ("httpHdrRangeSpecCanonize: have: [%ld, %ld) len: %ld\n",
	(long int) spec->offset, (long int) spec->offset + spec->length, (long int) spec->length);
    if (!known_spec(spec->offset))	/* suffix */
	spec->offset = size_diff(clen, spec->length);
    else if (!known_spec(spec->length))		/* trailer */
	spec->length = size_diff(clen, spec->offset);
    /* we have a "range" now, adjust length if needed */
    assert(known_spec(spec->length));
    assert(known_spec(spec->offset));
    spec->length = size_min(size_diff(clen, spec->offset), spec->length);
    /* check range validity */
    debug(64, 5) ("httpHdrRangeSpecCanonize: done: [%ld, %ld) len: %ld\n",
	(long int) spec->offset, (long int) spec->offset + (long int) spec->length, (long int) spec->length);
    return spec->length > 0;
}

/* merges recepient with donor if possible; returns true on success 
 * both specs must be canonized prior to merger, of course */
static int
httpHdrRangeSpecMergeWith(HttpHdrRangeSpec * recep, const HttpHdrRangeSpec * donor)
{
    int merged = 0;
#if MERGING_BREAKS_NOTHING
    /* Note: this code works, but some clients may not like its effects */
    size_t rhs = recep->offset + recep->length;		/* no -1 ! */
    const size_t donor_rhs = donor->offset + donor->length;	/* no -1 ! */
    assert(known_spec(recep->offset));
    assert(known_spec(donor->offset));
    assert(recep->length > 0);
    assert(donor->length > 0);
    /* do we have a left hand side overlap? */
    if (donor->offset < recep->offset && recep->offset <= donor_rhs) {
	recep->offset = donor->offset;	/* decrease left offset */
	merged = 1;
    }
    /* do we have a right hand side overlap? */
    if (donor->offset <= rhs && rhs < donor_rhs) {
	rhs = donor_rhs;	/* increase right offset */
	merged = 1;
    }
    /* adjust length if offsets have been changed */
    if (merged) {
	assert(rhs > recep->offset);
	recep->length = rhs - recep->offset;
    } else {
	/* does recepient contain donor? */
	merged =
	    recep->offset <= donor->offset && donor->offset < rhs;
    }
#endif
    return merged;
}

/*
 * Range
 */

static HttpHdrRange *
httpHdrRangeCreate(void)
{
    HttpHdrRange *r = memAllocate(MEM_HTTP_HDR_RANGE);
    stackInit(&r->specs);
    return r;
}

HttpHdrRange *
httpHdrRangeParseCreate(const String * str)
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
httpHdrRangeParseInit(HttpHdrRange * range, const String * str)
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
    pos = strBuf(*str) + 5;
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
    debug(64, 8) ("parsed range range count: %d\n", range->specs.count);
    return range->specs.count;
}

void
httpHdrRangeDestroy(HttpHdrRange * range)
{
    assert(range);
    while (range->specs.count)
	httpHdrRangeSpecDestroy(stackPop(&range->specs));
    stackClean(&range->specs);
    memFree(range, MEM_HTTP_HDR_RANGE);
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
    const HttpHdrRangeSpec *spec;
    assert(range);
    while ((spec = httpHdrRangeGetSpec(range, &pos))) {
	if (pos != HttpHdrRangeInitPos)
	    packerAppend(p, ",", 1);
	httpHdrRangeSpecPackInto(spec, p);
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
httpHdrRangeCanonize(HttpHdrRange * range, ssize_t clen)
{
    int i;
    HttpHdrRangeSpec *spec;
    HttpHdrRangePos pos = HttpHdrRangeInitPos;
    Stack goods;
    assert(range);
    assert(clen >= 0);
    stackInit(&goods);
    debug(64, 3) ("httpHdrRangeCanonize: started with %d specs, clen: %ld\n", range->specs.count, (long int) clen);

    /* canonize each entry and destroy bad ones if any */
    while ((spec = httpHdrRangeGetSpec(range, &pos))) {
	if (httpHdrRangeSpecCanonize(spec, clen))
	    stackPush(&goods, spec);
	else
	    httpHdrRangeSpecDestroy(spec);
    }
    debug(64, 3) ("httpHdrRangeCanonize: found %d bad specs\n",
	range->specs.count - goods.count);
    /* reset old array */
    stackClean(&range->specs);
    stackInit(&range->specs);
    spec = NULL;
    /* merge specs:
     * take one spec from "goods" and merge it with specs from 
     * "range->specs" (if any) until there is no overlap */
    for (i = 0; i < goods.count;) {
	HttpHdrRangeSpec *prev_spec = stackTop(&range->specs);
	spec = goods.items[i];
	if (prev_spec) {
	    if (httpHdrRangeSpecMergeWith(spec, prev_spec)) {
		/* merged with current so get rid of the prev one */
		assert(prev_spec == stackPop(&range->specs));
		httpHdrRangeSpecDestroy(prev_spec);
		continue;	/* re-iterate */
	    }
	}
	stackPush(&range->specs, spec);
	spec = NULL;
	i++;			/* progress */
    }
    if (spec)			/* last "merge" may not be pushed yet */
	stackPush(&range->specs, spec);
    debug(64, 3) ("httpHdrRangeCanonize: had %d specs, merged %d specs\n",
	goods.count, goods.count - range->specs.count);
    debug(64, 3) ("httpHdrRangeCanonize: finished with %d specs\n",
	range->specs.count);
    stackClean(&goods);
    return range->specs.count > 0;
}

/* searches for next range, returns true if found */
HttpHdrRangeSpec *
httpHdrRangeGetSpec(const HttpHdrRange * range, HttpHdrRangePos * pos)
{
    assert(range);
    assert(pos && *pos >= -1 && *pos < range->specs.count);
    (*pos)++;
    if (*pos < range->specs.count)
	return (HttpHdrRangeSpec *) range->specs.items[*pos];
    else
	return NULL;
}

/* hack: returns true if range specs are too "complex" for Squid to handle */
/* requires that specs are "canonized" first! */
int
httpHdrRangeIsComplex(const HttpHdrRange * range)
{
    HttpHdrRangePos pos = HttpHdrRangeInitPos;
    const HttpHdrRangeSpec *spec;
    size_t offset = 0;
    assert(range);
    /* check that all rangers are in "strong" order */
    while ((spec = httpHdrRangeGetSpec(range, &pos))) {
	if (spec->offset < offset)
	    return 1;
	offset = spec->offset + spec->length;
    }
    return 0;
}

/*
 * hack: returns true if range specs may be too "complex" when "canonized".
 * see also: httpHdrRangeIsComplex.
 */
int
httpHdrRangeWillBeComplex(const HttpHdrRange * range)
{
    HttpHdrRangePos pos = HttpHdrRangeInitPos;
    const HttpHdrRangeSpec *spec;
    size_t offset = 0;
    assert(range);
    /* check that all rangers are in "strong" order, */
    /* as far as we can tell without the content length */
    while ((spec = httpHdrRangeGetSpec(range, &pos))) {
	if (!known_spec(spec->offset))	/* ignore unknowns */
	    continue;
	if (spec->offset < offset)
	    return 1;
	offset = spec->offset;
	if (known_spec(spec->length))	/* avoid  unknowns */
	    offset += spec->length;
    }
    return 0;
}

/*
 * Returns lowest known offset in range spec(s), or range_spec_unknown
 * this is used for size limiting
 */
ssize_t
httpHdrRangeFirstOffset(const HttpHdrRange * range)
{
    ssize_t offset = range_spec_unknown;
    HttpHdrRangePos pos = HttpHdrRangeInitPos;
    const HttpHdrRangeSpec *spec;
    assert(range);
    while ((spec = httpHdrRangeGetSpec(range, &pos))) {
	if (spec->offset < offset || !known_spec(offset))
	    offset = spec->offset;
    }
    return offset;
}

/*
 * Returns lowest offset in range spec(s), 0 if unknown.
 * This is used for finding out where we need to start if all
 * ranges are combined into one, for example FTP REST.
 * Use 0 for size if unknown
 */
ssize_t
httpHdrRangeLowestOffset(const HttpHdrRange * range, ssize_t size)
{
    ssize_t offset = range_spec_unknown;
    ssize_t current;
    HttpHdrRangePos pos = HttpHdrRangeInitPos;
    const HttpHdrRangeSpec *spec;
    assert(range);
    while ((spec = httpHdrRangeGetSpec(range, &pos))) {
	current = spec->offset;
	if (!known_spec(current)) {
	    if (spec->length > size || !known_spec(spec->length))
		return 0;	/* Unknown. Assume start of file */
	    current = size - spec->length;
	}
	if (current < offset || !known_spec(offset))
	    offset = current;
    }
    return known_spec(offset) ? offset : 0;
}


/* generates a "unique" boundary string for multipart responses
 * the caller is responsible for cleaning the string */
String
httpHdrRangeBoundaryStr(clientHttpRequest * http)
{
    const char *key;
    String b = StringNull;
    assert(http);
    stringAppend(&b, full_appname_string, strlen(full_appname_string));
    stringAppend(&b, ":", 1);
    key = storeKeyText(http->entry->hash.key);
    stringAppend(&b, key, strlen(key));
    return b;
}

/*  
 * Return true if the first range offset is larger than the configured
 * limit.
 */
int
httpHdrRangeOffsetLimit(HttpHdrRange * range)
{
    if (NULL == range)
	/* not a range request */
	return 0;
    if (-1 == Config.rangeOffsetLimit)
	/* disabled */
	return 0;
    if (Config.rangeOffsetLimit >= httpHdrRangeFirstOffset(range))
	/* below the limit */
	return 0;
    return 1;
}
