/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPHDRCONTRANGE_H
#define SQUID_HTTPHDRCONTRANGE_H

#include "HttpHeaderRange.h"

class HttpHeader;

/** HTTP Content-Range: header field */
class HttpHdrContRange
{
    MEMPROXY_CLASS(HttpHdrContRange);

public:
    HttpHdrContRange() : elength(0) {}

    HttpHdrRangeSpec spec;
    int64_t elength;        /**< entity length, not content length */
};

/** \todo CLEANUP: Move httpHdrContRange* functions into the class methods */

HttpHdrContRange *httpHdrContRangeCreate(void);
HttpHdrContRange *httpHdrContRangeParseCreate(const char *crange_spec);
/** returns true if range is valid; inits HttpHdrContRange */
int httpHdrContRangeParseInit(HttpHdrContRange * crange, const char *crange_spec);
HttpHdrContRange *httpHdrContRangeDup(const HttpHdrContRange * crange);
void httpHdrContRangePackInto(const HttpHdrContRange * crange, Packable * p);
/** inits with given spec */
void httpHdrContRangeSet(HttpHdrContRange *, HttpHdrRangeSpec, int64_t);
void httpHeaderAddContRange(HttpHeader *, HttpHdrRangeSpec, int64_t);

#endif /* SQUID_HTTPHDRCONTRANGE_H */

