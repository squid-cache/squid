/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ERROR_EXCEPTIONERRORDETAIL_H
#define SQUID_SRC_ERROR_EXCEPTIONERRORDETAIL_H

#include "base/IoManip.h"
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
    SBuf brief() const override {
        return ToSBuf("exception=", asHex(exceptionId));
    }

    SBuf verbose(const HttpRequestPointer &) const override {
        return ToSBuf("Exception (ID=", asHex(exceptionId), ')');
    }

private:
    SourceLocationId exceptionId; ///< identifies the thrower or catcher
};

#endif /* SQUID_SRC_ERROR_EXCEPTIONERRORDETAIL_H */

