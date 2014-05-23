#include "squid.h"

#define STUB_API "carp.cc"
#include "tests/STUB.h"

class CachePeer;
class HttpRequest;

void carpInit(void) STUB
CachePeer * carpSelectParent(HttpRequest *) STUB_RETVAL(NULL)

