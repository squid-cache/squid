#include "config.h"
#include "STUB.h"
#include "StatHist.h"

#define STUB_API "StatHist.cc"

void
StatHist::init(int capacity_, hbase_f * val_in_, hbase_f * val_out_, double min_, double max_)
{}

StatHist::~StatHist()
{}

void
StatHist::enumInit(int last_enum)
{}

void
StatHist::count(double val)
{}

void
StatHist::dump(StoreEntry * sentry, StatHistBinDumper * bd) const
{}
