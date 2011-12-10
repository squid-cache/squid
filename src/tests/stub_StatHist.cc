#include "squid.h"

// for StatHist definitions
#include "StatHist.h"

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

void
StatHist::dump(StoreEntry * sentry, StatHistBinDumper * bd) const
{
    // noop
}
