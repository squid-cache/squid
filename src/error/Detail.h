/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_ERROR_DETAIL_H
#define _SQUID_SRC_ERROR_DETAIL_H

#include "base/Here.h"
#include "base/RefCount.h"
#include "error/forward.h"
#include "http/forward.h"
#include "mem/forward.h"
#include "sbuf/forward.h"

/// interface for supplying additional information about a transaction failure
class ErrorDetail: public RefCountable
{
public:
    using Pointer = ErrorDetailPointer;

    virtual ~ErrorDetail() {}

    /// \returns a single "token" summarizing available details
    /// suitable as an access.log field and similar output processed by programs
    virtual SBuf brief() const = 0;

    /// \returns all available details; may be customized for the given request
    /// suitable for error pages and other output meant for human consumption
    virtual SBuf verbose(const HttpRequestPointer &) const = 0;
};

/// creates a new NamedErrorDetail object with a unique name
/// \see NamedErrorDetail::Name for naming restrictions
ErrorDetail::Pointer MakeNamedErrorDetail(const char *name);

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

    static SBuf Brief(int errorNo);

    /* ErrorDetail API */
    virtual SBuf brief() const override;
    virtual SBuf verbose(const HttpRequestPointer &) const override;

private:
    // hidden by NewIfAny() to avoid creating SysErrorDetail from zero errno
    explicit SysErrorDetail(const int anErrorNo): errorNo(anErrorNo) {}

    int errorNo; ///< errno(3) set by the last failed system call or equivalent
};

/// offset for exception ID details, for backward compatibility
#define SQUID_EXCEPTION_START_BASE 110000

/// Details a failure reported via a C++ exception. Stores exception ID which
/// scripts/calc-must-ids.sh can map to a relevant source code location.
class ExceptionErrorDetail: public ErrorDetail
{
    MEMPROXY_CLASS(ExceptionErrorDetail);

public:
    explicit ExceptionErrorDetail(const SourceLocationId id): exceptionId(SQUID_EXCEPTION_START_BASE + id) {}

    /* ErrorDetail API */
    virtual SBuf brief() const override;
    virtual SBuf verbose(const HttpRequestPointer &) const override;

private:
    SourceLocationId exceptionId; ///< identifies the thrower or catcher
};

/// dump the given ErrorDetail (for debugging)
std::ostream &operator <<(std::ostream &os, const ErrorDetail &);

/// dump the given ErrorDetail pointer which may be nil (for debugging)
std::ostream &operator <<(std::ostream &os, const ErrorDetail::Pointer &);

#endif /* _SQUID_SRC_ERROR_DETAIL_H */

