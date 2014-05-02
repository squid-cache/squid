#include "squid.h"

#include "HttpReply.h"
#include "HttpRequest.h"

#define STUB_API "http.cc"
#include "tests/STUB.h"

const char * httpMakeVaryMark(HttpRequest * request, HttpReply const * reply) STUB_RETVAL(NULL)
