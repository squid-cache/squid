#include "config.h"
#include "stmem.h"

#define STUB_API "stmem.cc"
#include "tests/STUB.h"

mem_hdr::mem_hdr() STUB
mem_hdr::~mem_hdr() STUB
size_t mem_hdr::size() const STUB_RETVAL(0)
