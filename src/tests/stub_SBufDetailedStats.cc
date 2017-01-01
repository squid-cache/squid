/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "sbuf/SBuf.h"

#define STUB_API "sbuf/DetailedStats.cc"
#include "tests/STUB.h"

class StatHist;

void recordSBufSizeAtDestruct(SBuf::size_type) {} // STUB_NOP
const StatHist * collectSBufDestructTimeStats() STUB_RETVAL(nullptr)
void recordMemBlobSizeAtDestruct(SBuf::size_type) {} // STUB_NOP
const StatHist * collectMemBlobDestructTimeStats() STUB_RETVAL(nullptr)

