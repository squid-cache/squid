/*
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
#define SQUID_UNIT_TEST 1
#include "squid.h"

#if 0
//#include "Store.h"
//#include "client_side_request.h"
#endif

/** \todo CLEANUP: This file shoudl be called something_stub.cc */

#include "HttpHeaderRange.h"
#include "HttpHeader.h"
#include "Mem.h"

#if 0
#include "acl/Checklist.h"
#endif

void httpHeaderPutStr(HttpHeader * hdr, http_hdr_type type, const char *str)
{
    fatal ("dummy function\n");
}

HttpHeaderEntry *httpHeaderGetEntry(const HttpHeader * hdr, HttpHeaderPos * pos)
{
    fatal ("dummy function\n");
    return NULL;
}

String httpHeaderGetList(const HttpHeader * hdr, http_hdr_type id)
{
    fatal ("dummy function\n");
    return String();
}

int httpHeaderHas(const HttpHeader * hdr, http_hdr_type type)
{
    fatal ("dummy function\n");
    return 0;
}

void httpHeaderPutContRange(HttpHeader * hdr, const HttpHdrContRange * cr)
{
    fatal ("dummy function\n");
}

void
testRangeParser(char const *rangestring)
{
    String aString (rangestring);
    HttpHdrRange *range = HttpHdrRange::ParseCreate (&aString);

    if (!range)
        exit (1);

    HttpHdrRange copy(*range);

    assert (copy.specs.count == range->specs.count);

    HttpHdrRange::iterator pos = range->begin();

    assert (*pos);

    delete range;
}

HttpHdrRange *
rangeFromString(char const *rangestring)
{
    String aString (rangestring);
    HttpHdrRange *range = HttpHdrRange::ParseCreate (&aString);

    if (!range)
        exit (1);

    return range;
}

void
testRangeIter ()
{
    HttpHdrRange *range=rangeFromString("bytes=0-3, 1-, -2");
    assert (range->specs.count == 3);
    size_t counter = 0;
    HttpHdrRange::iterator i = range->begin();

    while (i != range->end()) {
        ++counter;
        ++i;
    }

    assert (counter == 3);
    i = range->begin();
    assert (i - range->begin() == 0);
    ++i;
    assert (i - range->begin() == 1);
    assert (i - range->end() == -2);
}

void
testRangeCanonization()
{
    HttpHdrRange *range=rangeFromString("bytes=0-3, 1-, -2");
    assert (range->specs.count == 3);

    /* 0-3 needs a content length of 4 */
    /* This passes in the extant code - but should it? */

    if (!range->canonize(3))
        exit(1);

    assert (range->specs.count == 3);

    delete range;

    range=rangeFromString("bytes=0-3, 1-, -2");

    assert (range->specs.count == 3);

    /* 0-3 needs a content length of 4 */
    if (!range->canonize(4))
        exit(1);

    delete range;

    range=rangeFromString("bytes=3-6");

    assert (range->specs.count == 1);

    /* 3-6 needs a content length of 4 or more */
    if (range->canonize(3))
        exit(1);

    delete range;

    range=rangeFromString("bytes=3-6");

    assert (range->specs.count == 1);

    /* 3-6 needs a content length of 4 or more */
    if (!range->canonize(4))
        exit(1);

    delete range;

    range=rangeFromString("bytes=1-1,2-3");

    assert (range->specs.count == 2);

    if (!range->canonize(4))
        exit(1);

    assert (range->specs.count == 2);

    delete range;
}

int
main(int argc, char **argv)
{
    try {
        Mem::Init();
        /* enable for debugging to console */
        //    _db_init (NULL, NULL);
        //    Debug::Levels[64] = 9;
        testRangeParser("bytes=0-3");
        testRangeParser("bytes=-3");
        testRangeParser("bytes=1-");
        testRangeParser("bytes=0-3, 1-, -2");
        testRangeIter();
        testRangeCanonization();
    } catch (const std::exception &e) {
        printf("Error: dying from an unhandled exception: %s\n", e.what());
        return 1;
    } catch (...) {
        printf("Error: dying from an unhandled exception.\n");
        return 1;
    }
    return 0;
}
