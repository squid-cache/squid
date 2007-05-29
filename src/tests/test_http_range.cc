
/*
 * $Id: test_http_range.cc,v 1.3 2007/05/29 13:31:48 amosjeffries Exp $
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
#include "Mem.h"
//#include "Store.h"
#include "HttpHeaderRange.h"
//#include "client_side_request.h"
#include "ACLChecklist.h"

/* Stub routines */
void
shut_down(int)
{}

SQUIDCEXTERN void httpHeaderPutStr(HttpHeader * hdr, http_hdr_type type, const char *str)
{
    fatal ("dummy function\n");
}

SQUIDCEXTERN HttpHeaderEntry *httpHeaderGetEntry(const HttpHeader * hdr, HttpHeaderPos * pos)
{
    fatal ("dummy function\n");
    return NULL;
}

extern String httpHeaderGetList(const HttpHeader * hdr, http_hdr_type id)
{
    fatal ("dummy function\n");
    return String();
}

SQUIDCEXTERN int httpHeaderHas(const HttpHeader * hdr, http_hdr_type type)
{
    fatal ("dummy function\n");
    return 0;
}

SQUIDCEXTERN void httpHeaderPutContRange(HttpHeader * hdr, const HttpHdrContRange * cr)
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
main (int argc, char **argv)
{
    Mem::Init();
    /* enable for debugging to console */
    //    _db_init (NULL, NULL);
    //    Debug::Levels[64] = 9;
    testRangeParser ("bytes=0-3");
    testRangeParser ("bytes=-3");
    testRangeParser ("bytes=1-");
    testRangeParser ("bytes=0-3, 1-, -2");
    testRangeIter ();
    testRangeCanonization();
    return 0;
}
