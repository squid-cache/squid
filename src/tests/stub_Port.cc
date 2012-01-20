#include "squid.h"
#include "ipc/Port.h"

#define STUB_API "ipc/Port.cc"
#include "tests/STUB.h"

const char Ipc::coordinatorAddr[] = "";
const char Ipc::strandAddrPfx[] = "";

String Ipc::Port::MakeAddr(char const*, int) STUB_RETVAL("")
