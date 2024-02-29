/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "StatHist.h"

#define STUB_API "StatHist.cc"
#include "tests/STUB.h"

class StoreEntry;

void StatHist::dump(StoreEntry *, StatHistBinDumper *) const STUB
void StatHist::enumInit(unsigned int) STUB_NOP
void StatHist::count(double) {/* STUB_NOP */}
double statHistDeltaMedian(const StatHist &, const StatHist &) STUB_RETVAL(0.0)
double statHistDeltaPctile(const StatHist &, const StatHist &, double) STUB_RETVAL(0.0)
void StatHist::logInit(unsigned int, double, double) STUB_NOP
void statHistIntDumper(StoreEntry *, int, double, double, int) STUB

