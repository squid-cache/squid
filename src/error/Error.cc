/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 04    Error Management */

#include "squid.h"
#include "base/IoManip.h"
#include "debug/Stream.h"
#include "error/Error.h"

/// reports the state before the update and updates category (if necessary)
/// \retval false indicates that the caller should quit (without any further
/// action like reporting update parameters and updating Error details)
bool
Error::startUpdate(const err_type recentCategory, const bool hasDetails)
{
    if (!recentCategory && !hasDetails)
        return false; // no changes

    if (*this)
        debugs(4, 5, "old: " << *this);

    // checking category and detail separately may cause inconsistency, but
    // may result in more details available if they only become available later
    if (category == ERR_NONE)
        category = recentCategory; // may still be ERR_NONE

    return true;
}

/// update existing details with the given one (if necessary)
void
Error::updateDetails(const ErrorDetail::Pointer &recentDetail)
{
    // an error can only have a few details so linear search is faster than indexing
    for (const auto &oldDetail: details) {
        if (recentDetail->equals(*oldDetail))
            return; // already present
    }
    details.push_back(recentDetail);
}

void
Error::update(const Error &recent)
{
    if (!startUpdate(recent.category, !recent.details.empty()))
        return; // no changes

    debugs(4, 3, "recent: " << recent);
    for (const auto &recentDetail: recent.details)
        updateDetails(recentDetail);
}

void
Error::update(const err_type recentCategory, const ErrorDetail::Pointer &recentDetail)
{
    if (!startUpdate(recentCategory, recentDetail != nullptr))
        return; // no changes

    debugs(4, 3, "recent: " << Error(recentCategory, recentDetail));
    if (recentDetail)
        updateDetails(recentDetail);
}

std::ostream &
operator <<(std::ostream &os, const ErrorDetails &details)
{
    os << AsList(details).delimitedBy('+');
    return os;
}

std::ostream &
operator <<(std::ostream &os, const Error &error)
{
    os << errorTypeName(error.category);
    os << AsList(error.details).prefixedBy('/').delimitedBy('+');
    return os;
}

