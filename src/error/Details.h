/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for detailss.
 */

#ifndef _SQUID_SRC_ERROR_DETAILS_H
#define _SQUID_SRC_ERROR_DETAILS_H

#include "error/Detail.h"

#include <vector>

/// Multiple details of a single error, in "canonical" order. Our "canonical"
/// order is the approximate discovery order (e.g., the order of Error::update()
/// calls) with no duplicates. This class isolates multi-detail storage
/// overheads from a common case of storing a single error detail.
class ErrorDetails: public ErrorDetail
{
public:
    /// Combines the already stored and the latest error details while
    /// preserving uniqueness and canonical order. Each parameter may point to a
    /// single detail or to an ErrorDetails object (with multiple details).
    static void Merge(ErrorDetailPointer &storage, const ErrorDetailPointer &latest);

    virtual ~ErrorDetails() = default;

protected:
    // use Merge() instead
    ErrorDetails() = default;

    void mergeOne(const ErrorDetail &);
    void mergeMany(const ErrorDetails &);

    /* ErrorDetail API */
    virtual SBuf brief() const override;
    virtual SBuf verbose(const HttpRequestPointer &) const override;

private:
    /// known unique details in canonical order
    std::vector<ErrorDetailPointer> details;
};

#endif /* _SQUID_SRC_ERROR_DETAILS_H */

