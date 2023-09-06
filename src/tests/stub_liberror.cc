/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "error/Error.h"
#include "sbuf/SBuf.h"

#define STUB_API "error/liberror.la"
#include "tests/STUB.h"

const char * err_type_str[ERR_MAX] = {};

void Error::update(const Error &) STUB_NOP

std::ostream &operator <<(std::ostream &os, const Error &) STUB_RETVAL(os)
std::ostream &operator <<(std::ostream &os, const ErrorDetail::Pointer &) STUB_RETVAL(os)

ErrorDetail::Pointer MakeNamedErrorDetail(const char *) STUB_RETVAL(ErrorDetail::Pointer())

#include "error/SysErrorDetail.h"
SBuf SysErrorDetail::Brief(int) STUB_RETVAL(SBuf())
SBuf SysErrorDetail::brief() const STUB_RETVAL(SBuf())
SBuf SysErrorDetail::verbose(const HttpRequestPointer &) const STUB_RETVAL(SBuf())
std::ostream &operator <<(std::ostream &os, ReportSysError) STUB_RETVAL(os)

