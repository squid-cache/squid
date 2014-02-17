#include "squid.h"
#include "ipc/Port.h"

#define STUB_API "ipc/Port.cc"
#include "tests/STUB.h"

const char Ipc::strandAddrLabel[] = "-kid";

String Ipc::Port::MakeAddr(char const*, int) STUB_RETVAL("")
String Ipc::Port::CoordinatorAddr() STUB_RETVAL("")
