/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPHEADERFIELDSTAT_H_
#define SQUID_HTTPHEADERFIELDSTAT_H_

/// per field statistics. Currently a POD.
class HttpHeaderFieldStat
{
public:
    HttpHeaderFieldStat() : aliveCount(0), seenCount(0), parsCount(0), errCount(0), repCount(0) {}

    int aliveCount;     /* created but not destroyed (count) */
    int seenCount;      /* number of fields we've seen */
    int parsCount;      /* number of parsing attempts */
    int errCount;       /* number of pasring errors */
    int repCount;       /* number of repetitons */
};

#endif /* SQUID_HTTPHEADERFIELDSTAT_H_ */

