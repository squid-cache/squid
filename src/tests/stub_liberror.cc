#include "squid.h"
#include "error/Error.h"
#include "sbuf/SBuf.h"

#define STUB_API "error/liberror.la"
#include "tests/STUB.h"

const char * err_type_str[ERR_MAX] = {};

void Error::update(const Error &) STUB_NOP

std::ostream &operator <<(std::ostream &os, const Error &) STUB_RETVAL(os)

ErrorDetail::Pointer MakeNamedErrorDetail(const char *name) STUB_RETVAL(ErrorDetail::Pointer())

