/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for detailss.
 */

#ifndef SQUID_SRC_ERROR_DETAILS_H
#define SQUID_SRC_ERROR_DETAILS_H

#include "error/Detail.h"
#include "mem/PoolingAllocator.h"

#include <vector>

/// Multiple details of a single error, in temporal order of discovery without duplicates.
/// The order/timing of Error::update() calls is used to approximate detail discovery time.
/// This class isolates multi-detail storage
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

    /// adds the given detail unless we already have it
    void mergeOne(const ErrorDetail &);

    /// adds unique details (if any) from the given collection
    void mergeMany(const ErrorDetails &);

    /* ErrorDetail API */
    virtual SBuf brief() const override;
    virtual SBuf verbose(const HttpRequestPointer &) const override;

private:
    /// known unique details in canonical order
    std::vector<ErrorDetailPointer, PoolingAllocator<ErrorDetailPointer> > details;
};

#endif /* SQUID_SRC_ERROR_DETAILS_H */

