/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "sbuf/DetailedStats.h"
#include "sbuf/SBuf.h"
#include "StatHist.h"

#define STUB_API "sbuf/DetailedStats.cc"
#include "tests/STUB.h"

static StatHist s;

void recordSBufSizeAtDestruct(SBuf::size_type) {} // STUB_NOP
StatHist &collectSBufDestructTimeStats() STUB_RETVAL(s)
void recordMemBlobSizeAtDestruct(SBuf::size_type) {} // STUB_NOP
StatHist &collectMemBlobDestructTimeStats() STUB_RETVAL(s)

