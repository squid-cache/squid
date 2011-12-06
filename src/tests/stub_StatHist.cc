#include "squid.h"

// for StatHist definitions
#include "StatHist.h"

void
statHistDump(const StatHist * H, StoreEntry * sentry, StatHistBinDumper * bd)
{
    fatal("statHistDump: Not implemented");
}

void
StatHist::count(double val)
{
    fatal("statHistCount: Not implemented");
}

void
statHistEnumInit(StatHist * H, int last_enum)
{
//NO-OP    fatal("statHistEnumInit: Not implemented");
}
