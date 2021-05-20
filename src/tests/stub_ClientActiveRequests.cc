#include "squid.h"
#include "ClientActiveRequests.h"

#define STUB_API "ClientActiveRequests.cc"
#include "tests/STUB.h"

dlink_list ClientActiveRequests;
void ClientActiveRequestsInit() STUB_NOP