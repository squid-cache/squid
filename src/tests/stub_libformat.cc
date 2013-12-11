#include "squid.h"
#include "format/Format.h"

#define STUB_API "stub_libformat.cc"
#include "tests/STUB.h"

void Format::Format::assemble(MemBuf &mb, const AccessLogEntryPointer &al, int logSequenceNumber) const STUB
bool Format::Format::parse(char const*) STUB_RETVAL(false)
Format::Format::Format(char const*) STUB
Format::Format::~Format() STUB
