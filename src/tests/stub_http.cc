#include "squid.h"

#define STUB_API "http.cc"
#include "tests/STUB.h"

const char * httpMakeVaryMark(HttpRequest * request, HttpReply const * reply) STUB_RETVAL(NULL)
