
/*
 * $Id: HttpHeaderRange.h,v 1.11 2007/08/13 17:20:51 hno Exp $
 *
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

#ifndef SQUID_HTTPHEADERRANGE_H
#define SQUID_HTTPHEADERRANGE_H

#include "MemPool.h"
#include "Range.h"
#include "Array.h"
#include "Packer.h"
#include "SquidString.h"

class HttpReply;
/* http byte-range-spec */

class HttpHdrRangeSpec
{

public:
    MEMPROXY_CLASS(HttpHdrRangeSpec);
    typedef Range<int64_t> HttpRange;
    static int64_t const UnknownPosition;

    HttpHdrRangeSpec();
    static HttpHdrRangeSpec *Create(const char *field, int fieldLen);

    bool parseInit(const char *field, int flen);
    int canonize(int64_t clen);
    void outputInfo( char const *note) const;
    void packInto(Packer * p) const;
    bool mergeWith(const HttpHdrRangeSpec * donor);
    int64_t offset;
    int64_t length;
};

MEMPROXY_CLASS_INLINE(HttpHdrRangeSpec)

/* There may be more than one byte range specified in the request.
 * This object holds all range specs in order of their appearence
 * in the request because we SHOULD preserve that order.
 */

class HttpHdrRange
{

public:
    MEMPROXY_CLASS(HttpHdrRange);

    static size_t ParsedCount;
    /* Http Range Header Field */
    static HttpHdrRange *ParseCreate(const String * range_spec);

    HttpHdrRange();
    HttpHdrRange(HttpHdrRange const &);
    ~HttpHdrRange();
    HttpHdrRange &operator= (HttpHdrRange const &);

    typedef Vector<HttpHdrRangeSpec *>::iterator iterator;
    typedef Vector<HttpHdrRangeSpec *>::const_iterator const_iterator;
    iterator begin();
    const_iterator begin () const;
    iterator end();
    const_iterator end() const;

    /* adjust specs after the length is known */
    int canonize(int64_t);
    int canonize(HttpReply *rep);
    /* returns true if ranges are valid; inits HttpHdrRange */
    bool parseInit(const String * range_spec);
    void packInto(Packer * p) const;
    /* other */
    bool isComplex() const;
    bool willBeComplex() const;
    int64_t firstOffset() const;
    int64_t lowestOffset(int64_t) const;
    bool offsetLimitExceeded() const;
    bool contains(HttpHdrRangeSpec& r) const;
    Vector<HttpHdrRangeSpec *> specs;

private:
    void getCanonizedSpecs (Vector<HttpHdrRangeSpec *> &copy);
    void merge (Vector<HttpHdrRangeSpec *> &basis);
    int64_t clen;
};

MEMPROXY_CLASS_INLINE(HttpHdrRange)

/* data for iterating thru range specs */

class HttpHdrRangeIter
{

public:
    HttpHdrRange::iterator pos;
    const HttpHdrRangeSpec *currentSpec() const;
    void updateSpec();
    int64_t debt() const;
    void debt(int64_t);
    int64_t debt_size;		/* bytes left to send from the current spec */
    String boundary;		/* boundary for multipart responses */
    bool valid;
};

#endif /* SQUID_HTTPHEADERRANGE_H */
