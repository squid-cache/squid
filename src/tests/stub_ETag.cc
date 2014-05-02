#include "squid.h"
#include "ETag.h"

#define STUB_API "ETag.cc"
#include "tests/STUB.h"

int etagParseInit(ETag * , const char *) STUB_RETVAL(0)
bool etagIsStrongEqual(const ETag &, const ETag &) STUB_RETVAL(false)
bool etagIsWeakEqual(const ETag &, const ETag &) STUB_RETVAL(false)

