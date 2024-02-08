/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ERROR_SYSERRORDETAIL_H
#define SQUID_SRC_ERROR_SYSERRORDETAIL_H

#include "error/Detail.h"
#include "sbuf/forward.h"

/// system call failure detail based on standard errno(3)/strerror(3) APIs
class SysErrorDetail: public ErrorDetail
{
    MEMPROXY_CLASS(SysErrorDetail);

public:
    /// \returns a pointer to a SysErrorDetail instance (or nil for lost errnos)
    static ErrorDetail::Pointer NewIfAny(const int errorNo)
    {
        // we could optimize by caching results for (frequently used?) errnos
        return errorNo ? new SysErrorDetail(errorNo) : nullptr;
    }

    /// \copydoc ErrorDetail::brief()
    static SBuf Brief(int errorNo);

    /* ErrorDetail API */
    SBuf brief() const override;
    SBuf verbose(const HttpRequestPointer &) const override;

private:
    // hidden by NewIfAny() to avoid creating SysErrorDetail from zero errno
    explicit SysErrorDetail(const int anErrorNo): errorNo(anErrorNo) {}

    int errorNo; ///< errno(3) set by the last failed system call or equivalent
};

/// a stream manipulator for printing a system call error (if any)
class ReportSysError
{
public:
    explicit ReportSysError(const int anErrorNo): errorNo(anErrorNo) {}
    int errorNo;
};

/// reports a system call error (if any) on a dedicated Debug::Extra line
std::ostream &operator <<(std::ostream &, ReportSysError);

#endif /* SQUID_SRC_ERROR_SYSERRORDETAIL_H */

