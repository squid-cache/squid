/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "StatHist.h"

#define STUB_API "StatHist.cc"
#include "STUB.h"

class StoreEntry;

void StatHist::dump(StoreEntry * sentry, StatHistBinDumper * bd) const STUB
void StatHist::enumInit(unsigned int i) STUB_NOP
void StatHist::count(double d) STUB_NOP
double statHistDeltaMedian(const StatHist & A, const StatHist & B) STUB_RETVAL(0.0)
double statHistDeltaPctile(const StatHist & A, const StatHist & B, double pctile) STUB_RETVAL(0.0)
void StatHist::logInit(unsigned int i, double d1, double d2) STUB
void statHistIntDumper(StoreEntry * sentry, int idx, double val, double size, int count) STUB

