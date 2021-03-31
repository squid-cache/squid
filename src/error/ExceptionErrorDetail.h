/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_ERROR_EXCEPTIONERRORDETAIL_H
#define _SQUID_SRC_ERROR_EXCEPTIONERRORDETAIL_H

#include "error/Detail.h"
#include "sbuf/SBuf.h"
#include "sbuf/Stream.h"

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
    virtual SBuf brief() const override {
        return ToSBuf("exception=", std::hex, exceptionId);
    }

    virtual SBuf verbose(const HttpRequestPointer &) const override {
        return ToSBuf("Exception (ID=", std::hex, exceptionId, ')');
    }

private:
    SourceLocationId exceptionId; ///< identifies the thrower or catcher
};

#endif /* _SQUID_SRC_ERROR_EXCEPTIONERRORDETAIL_H */

