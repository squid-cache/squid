#include "squid.h"
#include "MemBuf.h"

#define STUB_API "MemBuf.cc"
#include "tests/STUB.h"

mb_size_t MemBuf::spaceSize() const STUB_RETVAL(0)
mb_size_t MemBuf::potentialSpaceSize() const STUB_RETVAL(0)
void MemBuf::consume(mb_size_t sz) STUB
void MemBuf::append(const char *c, mb_size_t sz) STUB
void MemBuf::appended(mb_size_t sz) STUB
void MemBuf::truncate(mb_size_t sz) STUB
void MemBuf::terminate() STUB
void MemBuf::init(mb_size_t szInit, mb_size_t szMax) STUB
void MemBuf::init() STUB
void MemBuf::clean() STUB
void MemBuf::reset() STUB
int MemBuf::isNull() STUB_RETVAL(1)
void MemBuf::Printf(const char *fmt,...) STUB
void MemBuf::vPrintf(const char *fmt, va_list ap) STUB
FREE *MemBuf::freeFunc() STUB_RETVAL(NULL)

#if !_USE_INLINE_
#include "MemBuf.cci"
#endif

void memBufReport(MemBuf * mb) STUB
void packerToMemInit(Packer * p, MemBuf * mb) STUB
