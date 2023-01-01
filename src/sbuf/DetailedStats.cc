/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "sbuf/DetailedStats.h"
#include "StatHist.h"

/*
 * Implementation note: the purpose of this construct is to avoid adding
 * external dependencies to the SBuf code
 */

static StatHist *
newStatHist() {
    StatHist *stats = new StatHist;
    stats->logInit(100, 30.0, 128000.0);
    return stats;
}

StatHist &
collectSBufDestructTimeStats()
{
    static StatHist *stats = newStatHist();
    return *stats;
}

StatHist &
collectMemBlobDestructTimeStats()
{
    static StatHist *stats = newStatHist();
    return *stats;
}

void
recordSBufSizeAtDestruct(SBuf::size_type sz)
{
    collectSBufDestructTimeStats().count(static_cast<double>(sz));
}

void
recordMemBlobSizeAtDestruct(SBuf::size_type sz)
{
    collectMemBlobDestructTimeStats().count(static_cast<double>(sz));
}

