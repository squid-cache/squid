/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
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

/// dump the given ErrorDetail (for debugging)
std::ostream &operator <<(std::ostream &os, const ErrorDetail &);

/// dump the given ErrorDetail pointer which may be nil (for debugging)
std::ostream &operator <<(std::ostream &os, const ErrorDetail::Pointer &);

#endif /* _SQUID_SRC_ERROR_DETAIL_H */

