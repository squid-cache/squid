#include "squid.h"
#include "ipc/UdsOp.h"

#define STUB_API "UdsOp.cc"
#include "tests/STUB.h"

void Ipc::SendMessage(const String& toAddress, const TypedMsgHdr& message) STUB
