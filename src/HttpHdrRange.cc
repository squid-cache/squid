
/*
 * $Id: HttpHdrRange.cc,v 1.42 2007/04/30 16:56:09 wessels Exp $
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
#include "Store.h"
#include "HttpHeaderRange.h"
#include "client_side_request.h"
#include "HttpReply.h"

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
 *    using HttpHdrRangeSpec::UnknownPosition constant.
 *
 *    Note: when response length becomes known, we convert any range
 *    spec into type one above. (Canonization process).
 */


/* local routines */
#define known_spec(s) ((s) > HttpHdrRangeSpec::UnknownPosition)

/* globals */
size_t HttpHdrRange::ParsedCount = 0;
ssize_t const HttpHdrRangeSpec::UnknownPosition = -1;

/*
 * Range-Spec
 */

HttpHdrRangeSpec::HttpHdrRangeSpec() : offset(UnknownPosition), length(UnknownPosition){}

/* parses range-spec and returns new object on success */
HttpHdrRangeSpec *
HttpHdrRangeSpec::Create(const char *field, int flen)
{
    HttpHdrRangeSpec spec;

    if (!spec.parseInit(field, flen))
        return NULL;

    return new HttpHdrRangeSpec(spec);
}

bool
HttpHdrRangeSpec::parseInit(const char *field, int flen)
{
    const char *p;

    if (flen < 2)
        return false;

    /* is it a suffix-byte-range-spec ? */
    if (*field == '-') {
        if (!httpHeaderParseSize(field + 1, &length))
            return false;
    } else
        /* must have a '-' somewhere in _this_ field */
        if (!((p = strchr(field, '-')) || (p - field >= flen))) {
            debugs(64, 2, "ignoring invalid (missing '-') range-spec near: '" << field << "'");
            return false;
        } else {
            if (!httpHeaderParseSize(field, &offset))
                return false;

            p++;

            /* do we have last-pos ? */
            if (p - field < flen) {
                ssize_t last_pos;

                if (!httpHeaderParseSize(p, &last_pos))
                    return false;

                HttpHdrRangeSpec::HttpRange aSpec (offset, last_pos + 1);

                length = aSpec.size();
            }
        }

    /* we managed to parse, check if the result makes sence */
    if (length == 0) {
        debugs(64, 2, "ignoring invalid (zero length) range-spec near: '" << field << "'");
        return false;
    }

    return true;
}

void
HttpHdrRangeSpec::packInto(Packer * packer) const
{
    if (!known_spec(offset))	/* suffix */
        packerPrintf(packer, "-%ld", (long int) length);
    else if (!known_spec(length))		/* trailer */
        packerPrintf(packer, "%ld-", (long int) offset);
    else			/* range */
        packerPrintf(packer, "%ld-%ld",
                     (long int) offset, (long int) offset + length - 1);
}

void
HttpHdrRangeSpec::outputInfo( char const *note) const
{
    debugs(64, 5, "HttpHdrRangeSpec::canonize: " << note << ": [" <<
           (long int) offset << ", " << (long int) offset + length <<
           ") len: " << (long int) length);
}

/* fills "absent" positions in range specification based on response body size
 * returns true if the range is still valid
 * range is valid if its intersection with [0,length-1] is not empty
 */
int
HttpHdrRangeSpec::canonize(size_t clen)
{
    outputInfo ("have");
    HttpRange object(0, clen);

    if (!known_spec(offset))	/* suffix */
    {
        assert(known_spec(length));
        offset = object.intersection(HttpRange (clen - length, clen)).start;
    } else if (!known_spec(length))		/* trailer */
    {
        assert(known_spec(offset));
        HttpRange newRange = object.intersection(HttpRange (offset, clen));
        length = newRange.size();
    }
    /* we have a "range" now, adjust length if needed */
    assert(known_spec(length));

    assert(known_spec(offset));

    HttpRange newRange = object.intersection (HttpRange (offset, offset + length));

    length = newRange.size();

    outputInfo ("done");

    return length > 0;
}

/* merges recepient with donor if possible; returns true on success
 * both specs must be canonized prior to merger, of course */
bool
HttpHdrRangeSpec::mergeWith(const HttpHdrRangeSpec * donor)
{
    bool merged (false);
#if MERGING_BREAKS_NOTHING
    /* Note: this code works, but some clients may not like its effects */
    size_t rhs = offset + length;		/* no -1 ! */
    const size_t donor_rhs = donor->offset + donor->length;	/* no -1 ! */
    assert(known_spec(offset));
    assert(known_spec(donor->offset));
    assert(length > 0);
    assert(donor->length > 0);
    /* do we have a left hand side overlap? */

    if (donor->offset < offset && offset <= donor_rhs) {
        offset = donor->offset;	/* decrease left offset */
        merged = 1;
    }

    /* do we have a right hand side overlap? */
    if (donor->offset <= rhs && rhs < donor_rhs) {
        rhs = donor_rhs;	/* increase right offset */
        merged = 1;
    }

    /* adjust length if offsets have been changed */
    if (merged) {
        assert(rhs > offset);
        length = rhs - offset;
    } else {
        /* does recepient contain donor? */
        merged =
            offset <= donor->offset && donor->offset < rhs;
    }

#endif
    return merged;
}

/*
 * Range
 */

HttpHdrRange::HttpHdrRange () : clen (HttpHdrRangeSpec::UnknownPosition)
{}

HttpHdrRange *
HttpHdrRange::ParseCreate(const String * range_spec)
{
    HttpHdrRange *r = new HttpHdrRange;

    if (!r->parseInit(range_spec)) {
        delete r;
        r = NULL;
    }

    return r;
}

/* returns true if ranges are valid; inits HttpHdrRange */
bool
HttpHdrRange::parseInit(const String * range_spec)
{
    const char *item;
    const char *pos = NULL;
    int ilen;
    int count = 0;
    assert(this && range_spec);
    ++ParsedCount;
    debugs(64, 8, "parsing range field: '" << range_spec->buf() << "'");
    /* check range type */

    if (range_spec->caseCmp("bytes=", 6))
        return 0;

    /* skip "bytes="; hack! */
    pos = range_spec->buf() + 5;

    /* iterate through comma separated list */
    while (strListGetItem(range_spec, ',', &item, &ilen, &pos)) {
        HttpHdrRangeSpec *spec = HttpHdrRangeSpec::Create(item, ilen);
        /*
         * HTTP/1.1 draft says we must ignore the whole header field if one spec
         * is invalid. However, RFC 2068 just says that we must ignore that spec.
         */

        if (spec)
            specs.push_back(spec);

        ++count;
    }

    debugs(64, 8, "parsed range range count: " << count << ", kept " <<
           specs.size());
    return specs.count != 0;
}

HttpHdrRange::~HttpHdrRange()
{
    while (specs.size())
        delete specs.pop_back();
}

HttpHdrRange::HttpHdrRange(HttpHdrRange const &old) : specs()
{
    specs.reserve(old.specs.size());

    for (const_iterator i = old.begin(); i != old.end(); ++i)
        specs.push_back(new HttpHdrRangeSpec ( **i));

    assert(old.specs.size() == specs.size());
}

HttpHdrRange::iterator
HttpHdrRange::begin()
{
    return specs.begin();
}

HttpHdrRange::iterator
HttpHdrRange::end()
{
    return specs.end();
}

HttpHdrRange::const_iterator
HttpHdrRange::begin() const
{
    return specs.begin();
}

HttpHdrRange::const_iterator
HttpHdrRange::end() const
{
    return specs.end();
}

void
HttpHdrRange::packInto(Packer * packer) const
{
    const_iterator pos = begin();
    assert(this);

    while (pos != end()) {
        if (pos != begin())
            packerAppend(packer, ",", 1);

        (*pos)->packInto(packer);

        ++pos;
    }
}

void
HttpHdrRange::merge (Vector<HttpHdrRangeSpec *> &basis)
{
    /* reset old array */
    specs.clean();
    /* merge specs:
     * take one spec from "goods" and merge it with specs from 
     * "specs" (if any) until there is no overlap */
    iterator i = basis.begin();

    while (i != basis.end()) {
        if (specs.size() && (*i)->mergeWith(specs.back())) {
            /* merged with current so get rid of the prev one */
            delete specs.pop_back();
            continue;	/* re-iterate */
        }

        specs.push_back (*i);
        ++i;			/* progress */
    }

    debugs(64, 3, "HttpHdrRange::merge: had " << basis.size() <<
           " specs, merged " << basis.size() - specs.size() << " specs");
}


void
HttpHdrRange::getCanonizedSpecs (Vector<HttpHdrRangeSpec *> &copy)
{
    /* canonize each entry and destroy bad ones if any */

    for (iterator pos (begin()); pos != end(); ++pos) {
        if ((*pos)->canonize(clen))
            copy.push_back (*pos);
        else
            delete (*pos);
    }

    debugs(64, 3, "HttpHdrRange::getCanonizedSpecs: found " <<
           specs.size() - copy.size() << " bad specs");
}

#include "HttpHdrContRange.h"

/*
 * canonizes all range specs within a set preserving the order
 * returns true if the set is valid after canonization; 
 * the set is valid if 
 *   - all range specs are valid and 
 *   - there is at least one range spec
 */
int
HttpHdrRange::canonize(HttpReply *rep)
{
    assert(this && rep);

    if (rep->content_range)
        clen = rep->content_range->elength;
    else
        clen = rep->content_length;

    return canonize (clen);
}

int
HttpHdrRange::canonize (size_t newClen)
{
    clen = newClen;
    debugs(64, 3, "HttpHdrRange::canonize: started with " << specs.count <<
           " specs, clen: " << clen);
    Vector<HttpHdrRangeSpec*> goods;
    getCanonizedSpecs(goods);
    merge (goods);
    debugs(64, 3, "HttpHdrRange::canonize: finished with " << specs.count <<
           " specs");
    return specs.count > 0;
}

/* hack: returns true if range specs are too "complex" for Squid to handle */
/* requires that specs are "canonized" first! */
bool
HttpHdrRange::isComplex() const
{
    size_t offset = 0;
    assert(this);
    /* check that all rangers are in "strong" order */
    const_iterator pos (begin());

    while (pos != end()) {
        /* Ensure typecasts is safe */
        assert ((*pos)->offset >= 0);

        if ((unsigned int)(*pos)->offset < offset)
            return 1;

        offset = (*pos)->offset + (*pos)->length;

        ++pos;
    }

    return 0;
}

/*
 * hack: returns true if range specs may be too "complex" when "canonized".
 * see also: HttpHdrRange::isComplex.
 */
bool
HttpHdrRange::willBeComplex() const
{
    assert(this);
    /* check that all rangers are in "strong" order, */
    /* as far as we can tell without the content length */
    size_t offset = 0;

    for (const_iterator pos (begin()); pos != end(); ++pos) {
        if (!known_spec((*pos)->offset))	/* ignore unknowns */
            continue;

        /* Ensure typecasts is safe */
        assert ((*pos)->offset >= 0);

        if ((size_t) (*pos)->offset < offset)
            return true;

        offset = (*pos)->offset;

        if (known_spec((*pos)->length))	/* avoid  unknowns */
            offset += (*pos)->length;
    }

    return false;
}

/*
 * Returns lowest known offset in range spec(s),
 * or HttpHdrRangeSpec::UnknownPosition
 * this is used for size limiting
 */
ssize_t
HttpHdrRange::firstOffset() const
{
    ssize_t offset = HttpHdrRangeSpec::UnknownPosition;
    assert(this);
    const_iterator pos = begin();

    while (pos != end()) {
        if ((*pos)->offset < offset || !known_spec(offset))
            offset = (*pos)->offset;

        ++pos;
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
HttpHdrRange::lowestOffset(ssize_t size) const
{
    ssize_t offset = HttpHdrRangeSpec::UnknownPosition;
    const_iterator pos = begin();
    assert(this);

    while (pos != end()) {
        ssize_t current = (*pos)->offset;

        if (!known_spec(current)) {
            if ((*pos)->length > size || !known_spec((*pos)->length))
                return 0;	/* Unknown. Assume start of file */

            current = size - (*pos)->length;
        }

        if (current < offset || !known_spec(offset))
            offset = current;

        ++pos;
    }

    return known_spec(offset) ? offset : 0;
}

/*
 * Return true if the first range offset is larger than the configured
 * limit.
 * Note that exceeding the limit (returning true) results in only 
 * grabbing the needed range elements from the origin.
 */
bool
HttpHdrRange::offsetLimitExceeded() const
{
    if (NULL == this)
        /* not a range request */
        return false;

    if (-1 == (ssize_t)Config.rangeOffsetLimit)
        /* disabled */
        return false;

    if (firstOffset() == -1)
        /* tail request */
        return true;

    if ((ssize_t)Config.rangeOffsetLimit >= firstOffset())
        /* below the limit */
        return false;

    return true;
}

bool
HttpHdrRange::contains(HttpHdrRangeSpec& r) const
{
    assert(r.length >= 0);
    HttpHdrRangeSpec::HttpRange rrange(r.offset, r.offset + r.length);

    for (const_iterator i = begin(); i != end(); ++i) {
        HttpHdrRangeSpec::HttpRange irange((*i)->offset, (*i)->offset + (*i)->length);
        HttpHdrRangeSpec::HttpRange intersection = rrange.intersection(irange);

        if (intersection.start == irange.start && intersection.size() == irange.size())
            return true;
    }

    return false;
}

const HttpHdrRangeSpec *
HttpHdrRangeIter::currentSpec() const
{
    if (pos.incrementable())
        return *pos;

    return NULL;
}

void
HttpHdrRangeIter::updateSpec()
{
    assert (debt_size == 0);
    assert (valid);

    if (pos.incrementable()) {
        debt(currentSpec()->length);
    }
}

ssize_t
HttpHdrRangeIter::debt() const
{
    debugs(64, 3, "HttpHdrRangeIter::debt: debt is " << debt_size);
    return debt_size;
}

void HttpHdrRangeIter::debt(ssize_t newDebt)
{
    debugs(64, 3, "HttpHdrRangeIter::debt: was " << debt_size << " now " << newDebt);
    debt_size = newDebt;
}
