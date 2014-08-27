#include "squid.h"

#define STUB_API "tunnel.cc"
#include "tests/STUB.h"

#include "FwdState.h"
class ClientHttpRequest;

void tunnelStart(ClientHttpRequest *, int64_t *, int *, const AccessLogEntryPointer &al) STUB

void switchToTunnel(HttpRequest *request, int *status_ptr, Comm::ConnectionPointer &clientConn, Comm::ConnectionPointer &srvConn) STUB

