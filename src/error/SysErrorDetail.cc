/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for sys_error_details.
 */

#include "squid.h"
#include "error/SysErrorDetail.h"
#include "sbuf/SBuf.h"
#include "sbuf/Stream.h"

SBuf
SysErrorDetail::Brief(int errorNo)
{
    return SysErrorDetail(errorNo).brief();
}

SBuf
SysErrorDetail::brief() const
{
    return ToSBuf("errno=", errorNo);
}

SBuf
SysErrorDetail::verbose(const HttpRequestPointer &) const
{
    return SBuf(xstrerr(errorNo));
}

std::ostream &
operator <<(std::ostream &os, const ReportSysError rse)
{
    if (const auto errorNo = rse.errorNo)
        os << Debug::Extra << "system call error: " << xstrerr(errorNo);
    return os;
}

