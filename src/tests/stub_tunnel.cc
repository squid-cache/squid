#include "squid.h"

#define STUB_API "tunnel.cc"
#include "tests/STUB.h"

#include "FwdState.h"
class ClientHttpRequest;

void tunnelStart(ClientHttpRequest *, int64_t *, int *, const AccessLogEntryPointer &al) STUB

