#include "squid.h"
#include "redirect.h"

#define STUB_API "redirect.cc"
#include "tests/STUB.h"

void redirectInit(void) STUB
void redirectShutdown(void) STUB
void redirectStart(ClientHttpRequest *, HLPCB *, void *) STUB
void storeIdStart(ClientHttpRequest *, HLPCB *, void *) STUB
