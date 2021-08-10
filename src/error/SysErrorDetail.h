/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_ERROR_SYSERRORDETAIL_H
#define _SQUID_SRC_ERROR_SYSERRORDETAIL_H

#include "error/Detail.h"
#include "sbuf/SBuf.h"
#include "sbuf/Stream.h"

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

    static SBuf Brief(int errorNo) {
        return SysErrorDetail(errorNo).brief();
    }

    /* ErrorDetail API */
    virtual SBuf brief() const override {
        return ToSBuf("errno=", errorNo);
    }

    virtual SBuf verbose(const HttpRequestPointer &) const override {
        return SBuf(strerror(errorNo));
    }

private:
    // hidden by NewIfAny() to avoid creating SysErrorDetail from zero errno
    explicit SysErrorDetail(const int anErrorNo): errorNo(anErrorNo) {}

    int errorNo; ///< errno(3) set by the last failed system call or equivalent
};

#endif /* _SQUID_SRC_ERROR_SYSERRORDETAIL_H */

