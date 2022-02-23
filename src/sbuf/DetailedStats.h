/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SBUFDETAILEDSTATS_H
#define SQUID_SBUFDETAILEDSTATS_H

#include "sbuf/SBuf.h"

class StatHist;

/// Record the size a SBuf had when it was destructed
void recordSBufSizeAtDestruct(SBuf::size_type sz);

/// the SBuf size-at-destruct-time histogram
StatHist &collectSBufDestructTimeStats();

/// Record the size a MemBlob had when it was destructed
void recordMemBlobSizeAtDestruct(MemBlob::size_type sz);

/// the MemBlob size-at-destruct-time histogram
StatHist &collectMemBlobDestructTimeStats();

#endif /* SQUID_SBUFDETAILEDSTATS_H */

