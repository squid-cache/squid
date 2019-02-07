/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPHEADERRANGE_H
#define SQUID_HTTPHEADERRANGE_H

#include "mem/forward.h"
#include "Range.h"
#include "SquidString.h"

#include <vector>

class HttpReply;
class Packable;

/* http byte-range-spec */

class HttpHdrRangeSpec
{
    MEMPROXY_CLASS(HttpHdrRangeSpec);

public:
    typedef Range<int64_t, uint64_t> HttpRange;
    static int64_t const UnknownPosition;

    HttpHdrRangeSpec();
    static HttpHdrRangeSpec *Create(const char *field, int fieldLen);

    bool parseInit(const char *field, int flen);
    int canonize(int64_t clen);
    void outputInfo( char const *note) const;
    void packInto(Packable * p) const;
    bool mergeWith(const HttpHdrRangeSpec * donor);
    int64_t offset;
    int64_t length;
};

/**
 * There may be more than one byte range specified in the request.
 * This object holds all range specs in order of their appearence
 * in the request because we SHOULD preserve that order.
 */
class HttpHdrRange
{
    MEMPROXY_CLASS(HttpHdrRange);

public:
    static size_t ParsedCount;
    /* Http Range Header Field */
    static HttpHdrRange *ParseCreate(const String * range_spec);

    HttpHdrRange();
    HttpHdrRange(HttpHdrRange const &);
    ~HttpHdrRange();
    HttpHdrRange &operator= (HttpHdrRange const &);

    typedef std::vector<HttpHdrRangeSpec *>::iterator iterator;
    typedef std::vector<HttpHdrRangeSpec *>::const_iterator const_iterator;
    iterator begin();
    const_iterator begin () const;
    iterator end();
    const_iterator end() const;

    /* adjust specs after the length is known */
    int canonize(int64_t);
    int canonize(HttpReply *rep);
    /* returns true if ranges are valid; inits HttpHdrRange */
    bool parseInit(const String * range_spec);
    void packInto(Packable * p) const;
    /* other */
    bool isComplex() const;
    bool willBeComplex() const;
    int64_t firstOffset() const;
    int64_t lowestOffset(int64_t) const;
    bool offsetLimitExceeded(const int64_t limit) const;
    bool contains(const HttpHdrRangeSpec& r) const;
    std::vector<HttpHdrRangeSpec *> specs;

private:
    void getCanonizedSpecs (std::vector<HttpHdrRangeSpec *> &copy);
    void merge (std::vector<HttpHdrRangeSpec *> &basis);
    int64_t clen;
};

/**
 * Data for iterating thru range specs
 */
class HttpHdrRangeIter
{

public:
    HttpHdrRange::iterator pos;
    HttpHdrRange::iterator end;
    const HttpHdrRangeSpec *currentSpec() const;
    void updateSpec();
    int64_t debt() const;
    void debt(int64_t);
    int64_t debt_size;      /* bytes left to send from the current spec */
    String boundary;        /* boundary for multipart responses */
    bool valid;
};

#endif /* SQUID_HTTPHEADERRANGE_H */

