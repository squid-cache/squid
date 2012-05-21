#include "squid.h"
#define STUB_API "StatHist.cc"
#include "STUB.h"
#include "StatHist.h"


void
StatHist::dump(StoreEntry * sentry, StatHistBinDumper * bd) const
{}

void
StatHist::enumInit(unsigned int i)
{}

void
StatHist::count(double d)
{}

double
statHistDeltaMedian(const StatHist & A, const StatHist & B)
STUB_RETVAL(0.0)

double
statHistDeltaPctile(const StatHist & A, const StatHist & B, double pctile)
STUB_RETVAL(0.0)

void
StatHist::logInit(unsigned int i, double d1, double d2)
STUB

class StoreEntry;
void
statHistIntDumper(StoreEntry * sentry, int idx, double val, double size, int count)
STUB

