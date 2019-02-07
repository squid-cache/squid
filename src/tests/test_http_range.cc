/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 64    HTTP Range Header */

#include "squid.h"
#include "fatal.h"
#include "HttpHeader.h"
#include "HttpHeaderRange.h"

/** \todo CLEANUP: This file should be called something_stub.cc */

void httpHeaderPutStr(HttpHeader * hdr, Http::HdrType type, const char *str)
{
    fatal ("dummy function\n");
}

HttpHeaderEntry *httpHeaderGetEntry(const HttpHeader * hdr, HttpHeaderPos * pos)
{
    fatal ("dummy function\n");
    return NULL;
}

String httpHeaderGetList(const HttpHeader * hdr, Http::HdrType id)
{
    fatal ("dummy function\n");
    return String();
}

int httpHeaderHas(const HttpHeader * hdr, Http::HdrType type)
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

    assert (copy.specs.size() == range->specs.size());

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
    assert (range->specs.size() == 3);
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
    assert (range->specs.size() == 3);

    /* 0-3 needs a content length of 4 */
    /* This passes in the extant code - but should it? */

    if (!range->canonize(3))
        exit(1);

    assert (range->specs.size() == 3);

    delete range;

    range=rangeFromString("bytes=0-3, 1-, -2");

    assert (range->specs.size() == 3);

    /* 0-3 needs a content length of 4 */
    if (!range->canonize(4))
        exit(1);

    delete range;

    range=rangeFromString("bytes=3-6");

    assert (range->specs.size() == 1);

    /* 3-6 needs a content length of 4 or more */
    if (range->canonize(3))
        exit(1);

    delete range;

    range=rangeFromString("bytes=3-6");

    assert (range->specs.size() == 1);

    /* 3-6 needs a content length of 4 or more */
    if (!range->canonize(4))
        exit(1);

    delete range;

    range=rangeFromString("bytes=1-1,2-3");

    assert (range->specs.size()== 2);

    if (!range->canonize(4))
        exit(1);

    assert (range->specs.size() == 2);

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

