/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "SBuf.h"

#define STUB_API "SBufDetailedStats.cc"
#include "tests/STUB.h"

class StatHist;

void recordSBufSizeAtDestruct(SBuf::size_type) {}
const StatHist * collectSBufDestructTimeStats() STUB_RETVAL(NULL)
void recordMemBlobSizeAtDestruct(SBuf::size_type) {}
const StatHist * collectMemBlobDestructTimeStats() STUB_RETVAL(NULL)

