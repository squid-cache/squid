/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 64    HTTP Range Header */

#include "squid.h"
#include "client_side_request.h"
#include "http/Stream.h"
#include "HttpHeaderRange.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "Store.h"
#include "StrList.h"

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
int64_t const HttpHdrRangeSpec::UnknownPosition = -1;

/*
 * Range-Spec
 */

HttpHdrRangeSpec::HttpHdrRangeSpec() : offset(UnknownPosition), length(UnknownPosition) {}

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
        if (!httpHeaderParseOffset(field + 1, &length) || !known_spec(length))
            return false;
    } else
        /* must have a '-' somewhere in _this_ field */
        if (!((p = strchr(field, '-')) && (p - field < flen))) {
            debugs(64, 2, "invalid (missing '-') range-spec near: '" << field << "'");
            return false;
        } else {
            if (!httpHeaderParseOffset(field, &offset) || !known_spec(offset))
                return false;

            ++p;

            /* do we have last-pos ? */
            if (p - field < flen) {
                int64_t last_pos;

                if (!httpHeaderParseOffset(p, &last_pos) || !known_spec(last_pos))
                    return false;

                // RFC 2616 s14.35.1 MUST: last-byte-pos >= first-byte-pos
                if (last_pos < offset) {
                    debugs(64, 2, "invalid (last-byte-pos < first-byte-pos) range-spec near: " << field);
                    return false;
                }

                HttpHdrRangeSpec::HttpRange aSpec (offset, last_pos + 1);

                length = aSpec.size();
            }
        }

    return true;
}

void
HttpHdrRangeSpec::packInto(Packable * p) const
{
    if (!known_spec(offset))    /* suffix */
        p->appendf("-%" PRId64, length);
    else if (!known_spec(length))       /* trailer */
        p->appendf("%" PRId64 "-", offset);
    else            /* range */
        p->appendf("%" PRId64 "-%" PRId64, offset, offset + length - 1);
}

void
HttpHdrRangeSpec::outputInfo( char const *note) const
{
    debugs(64, 5, "HttpHdrRangeSpec::canonize: " << note << ": [" <<
           offset << ", " << offset + length <<
           ") len: " << length);
}

/* fills "absent" positions in range specification based on response body size
 * returns true if the range is still valid
 * range is valid if its intersection with [0,length-1] is not empty
 */
int
HttpHdrRangeSpec::canonize(int64_t clen)
{
    outputInfo ("have");
    HttpRange object(0, clen);

    if (!known_spec(offset)) {  /* suffix */
        assert(known_spec(length));
        offset = object.intersection(HttpRange (clen - length, clen)).start;
    } else if (!known_spec(length)) {   /* trailer */
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
    int64_t rhs = offset + length;      /* no -1 ! */
    const int64_t donor_rhs = donor->offset + donor->length;    /* no -1 ! */
    assert(known_spec(offset));
    assert(known_spec(donor->offset));
    assert(length > 0);
    assert(donor->length > 0);
    /* do we have a left hand side overlap? */

    if (donor->offset < offset && offset <= donor_rhs) {
        offset = donor->offset; /* decrease left offset */
        merged = 1;
    }

    /* do we have a right hand side overlap? */
    if (donor->offset <= rhs && rhs < donor_rhs) {
        rhs = donor_rhs;    /* increase right offset */
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

HttpHdrRange::HttpHdrRange() : clen(HttpHdrRangeSpec::UnknownPosition)
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
    assert(range_spec);
    ++ParsedCount;
    debugs(64, 8, "parsing range field: '" << range_spec << "'");
    /* check range type */

    if (range_spec->caseCmp("bytes=", 6))
        return 0;

    /* skip "bytes="; hack! */
    pos = range_spec->termedBuf() + 6;

    /* iterate through comma separated list */
    while (strListGetItem(range_spec, ',', &item, &ilen, &pos)) {
        HttpHdrRangeSpec *spec = HttpHdrRangeSpec::Create(item, ilen);
        /*
         * RFC 2616 section 14.35.1: MUST ignore Range with
         * at least one syntactically invalid byte-range-specs.
         */
        if (!spec) {
            while (!specs.empty()) {
                delete specs.back();
                specs.pop_back();
            }
            debugs(64, 2, "ignoring invalid range field: '" << range_spec << "'");
            break;
        }

        specs.push_back(spec);
    }

    debugs(64, 8, "got range specs: " << specs.size());
    return !specs.empty();
}

HttpHdrRange::~HttpHdrRange()
{
    while (!specs.empty()) {
        delete specs.back();
        specs.pop_back();
    }
}

HttpHdrRange::HttpHdrRange(HttpHdrRange const &old) :
    specs(),
    clen(HttpHdrRangeSpec::UnknownPosition)
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
HttpHdrRange::packInto(Packable * packer) const
{
    const_iterator pos = begin();

    while (pos != end()) {
        if (pos != begin())
            packer->append(",", 1);

        (*pos)->packInto(packer);

        ++pos;
    }
}

void
HttpHdrRange::merge (std::vector<HttpHdrRangeSpec *> &basis)
{
    /* reset old array */
    specs.clear();
    /* merge specs:
     * take one spec from "goods" and merge it with specs from
     * "specs" (if any) until there is no overlap */
    iterator i = basis.begin();

    while (i != basis.end()) {
        if (specs.size() && (*i)->mergeWith(specs.back())) {
            /* merged with current so get rid of the prev one */
            delete specs.back();
            specs.pop_back();
            continue;   /* re-iterate */
        }

        specs.push_back (*i);
        ++i;            /* progress */
    }

    debugs(64, 3, "HttpHdrRange::merge: had " << basis.size() <<
           " specs, merged " << basis.size() - specs.size() << " specs");
}

void
HttpHdrRange::getCanonizedSpecs(std::vector<HttpHdrRangeSpec *> &copy)
{
    /* canonize each entry and destroy bad ones if any */

    for (iterator pos (begin()); pos != end(); ++pos) {
        if ((*pos)->canonize(clen))
            copy.push_back (*pos);
        else
            delete (*pos);
    }

    debugs(64, 3, "found " << specs.size() - copy.size() << " bad specs");
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
    assert(rep);

    if (rep->contentRange())
        clen = rep->contentRange()->elength;
    else
        clen = rep->content_length;

    return canonize (clen);
}

int
HttpHdrRange::canonize (int64_t newClen)
{
    clen = newClen;
    debugs(64, 3, "HttpHdrRange::canonize: started with " << specs.size() <<
           " specs, clen: " << clen);
    std::vector<HttpHdrRangeSpec*> goods;
    getCanonizedSpecs(goods);
    merge (goods);
    debugs(64, 3, "HttpHdrRange::canonize: finished with " << specs.size() <<
           " specs");
    return specs.size() > 0; // fixme, should return bool
}

/* hack: returns true if range specs are too "complex" for Squid to handle */
/* requires that specs are "canonized" first! */
bool
HttpHdrRange::isComplex() const
{
    int64_t offset = 0;
    /* check that all rangers are in "strong" order */
    const_iterator pos (begin());

    while (pos != end()) {
        /* Ensure typecasts is safe */
        assert ((*pos)->offset >= 0);

        if ((*pos)->offset < offset)
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
    /* check that all rangers are in "strong" order, */
    /* as far as we can tell without the content length */
    int64_t offset = 0;

    for (const_iterator pos (begin()); pos != end(); ++pos) {
        if (!known_spec((*pos)->offset))    /* ignore unknowns */
            continue;

        /* Ensure typecasts is safe */
        assert ((*pos)->offset >= 0);

        if ((*pos)->offset < offset)
            return true;

        offset = (*pos)->offset;

        if (known_spec((*pos)->length)) /* avoid  unknowns */
            offset += (*pos)->length;
    }

    return false;
}

/*
 * Returns lowest known offset in range spec(s),
 * or HttpHdrRangeSpec::UnknownPosition
 * this is used for size limiting
 */
int64_t
HttpHdrRange::firstOffset() const
{
    int64_t offset = HttpHdrRangeSpec::UnknownPosition;
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
int64_t
HttpHdrRange::lowestOffset(int64_t size) const
{
    int64_t offset = HttpHdrRangeSpec::UnknownPosition;
    const_iterator pos = begin();

    while (pos != end()) {
        int64_t current = (*pos)->offset;

        if (!known_spec(current)) {
            if ((*pos)->length > size || !known_spec((*pos)->length))
                return 0;   /* Unknown. Assume start of file */

            current = size - (*pos)->length;
        }

        if (current < offset || !known_spec(offset))
            offset = current;

        ++pos;
    }

    return known_spec(offset) ? offset : 0;
}

/*
 * \retval true   Fetch only requested ranges. The first range is larger that configured limit.
 * \retval false  Full download. Not a range request, no limit, or the limit is not yet reached.
 */
bool
HttpHdrRange::offsetLimitExceeded(const int64_t limit) const
{
    if (limit == 0)
        /* 0 == disabled */
        return true;

    if (-1 == limit)
        /* 'none' == forced */
        return false;

    if (firstOffset() == -1)
        /* tail request */
        return true;

    if (limit >= firstOffset())
        /* below the limit */
        return false;

    return true;
}

bool
HttpHdrRange::contains(const HttpHdrRangeSpec& r) const
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
    if (pos != end)
        return *pos;

    return NULL;
}

void
HttpHdrRangeIter::updateSpec()
{
    assert (debt_size == 0);
    assert (valid);

    if (pos != end) {
        debt(currentSpec()->length);
    }
}

int64_t
HttpHdrRangeIter::debt() const
{
    debugs(64, 3, "HttpHdrRangeIter::debt: debt is " << debt_size);
    return debt_size;
}

void HttpHdrRangeIter::debt(int64_t newDebt)
{
    debugs(64, 3, "HttpHdrRangeIter::debt: was " << debt_size << " now " << newDebt);
    debt_size = newDebt;
}

