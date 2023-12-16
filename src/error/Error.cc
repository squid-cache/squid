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

void
Error::update(const err_type recentCategory)
{
    if (recentCategory == ERR_NONE)
        return; // no category given

    if (category == recentCategory)
        return; // no new category given

    if (category != ERR_NONE) {
        debugs(4, 5, "ignoring: " << errorTypeName(recentCategory) << "; keeping " << *this);
        return; // the category given earlier has won
    }

    category = recentCategory;
    debugs(4, 3, "new: " << errorTypeName(category));
}

void
Error::update(const ErrorDetail::Pointer &recentDetail)
{
    if (!recentDetail)
        return; // no new detail given

    // an error can only have a few details so linear search is faster than indexing
    for (const auto &oldDetail: details) {
        if (recentDetail->equals(*oldDetail))
            return; // the given detail is already present
    }

    details.push_back(recentDetail);
    debugs(4, 3, "new: " << recentDetail);
}

void
Error::update(const Error &recent)
{
    // checking category and detail separately may cause inconsistency, but
    // may result in more details available if they only become available later
    update(recent.category);
    for (const auto &recentDetail: recent.details)
        update(recentDetail);
}

void
Error::update(const err_type recentCategory, const ErrorDetail::Pointer &recentDetail)
{
    // Optimization: Do not simply call update(Error(...)) here because that
    // would require allocating and freeing heap memory for storing the detail.
    update(recentCategory);
    update(recentDetail);
}

std::ostream &
operator <<(std::ostream &os, const ErrorDetails &details)
{
    os << AsList(details).delimitedBy("+");
    return os;
}

std::ostream &
operator <<(std::ostream &os, const Error &error)
{
    os << errorTypeName(error.category);
    os << AsList(error.details).prefixedBy("/").delimitedBy("+");
    return os;
}

