/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "SBufDetailedStats.h"
#include "StatHist.h"

/*
 * Implementation note: the purpose of this construct is to avoid adding
 * external dependencies to the SBuf code
 */

static StatHist sbufDestructTimeStats;
static StatHist memblobDestructTimeStats;

namespace SBufDetailedStatsHistInitializer
{
// run the post-instantiation initialization methods for StatHist objects
struct Initializer {
    Initializer() {
        sbufDestructTimeStats.logInit(100,30.0,128000.0);
        memblobDestructTimeStats.logInit(100,30.0,128000.0);
    }
};
Initializer initializer;
}

void
recordSBufSizeAtDestruct(SBuf::size_type sz)
{
    sbufDestructTimeStats.count(static_cast<double>(sz));
}

const StatHist *
collectSBufDestructTimeStats()
{
    return &sbufDestructTimeStats;
}

void
recordMemBlobSizeAtDestruct(SBuf::size_type sz)
{
    memblobDestructTimeStats.count(static_cast<double>(sz));
}

const StatHist *
collectMemBlobDestructTimeStats()
{
    return &memblobDestructTimeStats;
}

