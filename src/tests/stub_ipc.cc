#include "squid.h"
#include "SquidIpc.h"

#define STUB_API "ipc.cc"
#include "tests/STUB.h"

pid_t ipcCreate(int, const char *, const char *const [], const char *, Ip::Address &, int *, int *, void **) STUB_RETVAL(-1)
