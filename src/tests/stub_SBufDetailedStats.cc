#include "squid.h"
#include "SBuf.h"

#define STUB_API "SBufDetailedStats.cc"
#include "tests/STUB.h"

class StatHist;

void recordSBufSizeAtDestruct(SBuf::size_type) {}
const StatHist * collectSBufDestructTimeStats() STUB_RETVAL(NULL)
void recordMemBlobSizeAtDestruct(SBuf::size_type) {}
const StatHist * collectMemBlobDestructTimeStats() STUB_RETVAL(NULL)
