/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Assure.h"
#include "error/Details.h"
#include "sbuf/SBuf.h"

static inline
bool
Same(const ErrorDetail &d1, const ErrorDetail &d2)
{
    // Duplicate details for the same error typically happen when we update some
    // error storage (e.g., ALE) twice from the same source or retag the error
    // with the same context information (e.g., WITH_CLIENT). In all those
    // cases, comparing detail object addresses is enough to detect duplicates.
    return &d1 == &d2;
}

void
ErrorDetails::Merge(ErrorDetailPointer &storage, const ErrorDetailPointer &latest)
{
    // The checks below avoid creating new ErrorDetails storage until we have
    // multiple _unique_ details to store.

    if (!latest)
        return; // x + 0

    const auto latestGroup = dynamic_cast<const ErrorDetails*>(latest.getRaw());

    if (!storage && !latestGroup) {
        storage = latest;
        return; // 0 + 1
    }

    if (!storage) {
        storage = new ErrorDetails(*latestGroup);
        return; // 0 + n
    }

    auto storedGroup = dynamic_cast<ErrorDetails*>(storage.getRaw()); // may be set later

    if (!storedGroup && !latestGroup && Same(*storage, *latest))
        return; // 1 + 1 but both are the same

    if (!storedGroup) {
        // move a single stored detail into ErrorDetails storage we can merge into
        storedGroup = new ErrorDetails();
        storedGroup->mergeOne(*storage);
        storage = storedGroup;
    }

    if (!latestGroup)
        storedGroup->mergeOne(*latest); // x + 1
    else
        storedGroup->mergeMany(*latestGroup); // x + n
}

/// adds the given detail unless we already have it
void
ErrorDetails::mergeOne(const ErrorDetail &detail)
{
    // brief()/verbose() do not support nested details or detail groups (yet?)
    Assure(!dynamic_cast<const ErrorDetails*>(&detail));
    // nobody should add a detail to itself
    Assure(!Same(*this, detail)); // paranoid due to the above Assure()

    // an error can only have a few details so vector+linear search is faster
    for (const auto &existingDetail: details) {
        if (Same(*existingDetail, detail))
            return; // already covered
    }
    details.emplace_back(&detail);
}

/// adds unique details (if any) from the given collection
void
ErrorDetails::mergeMany(const ErrorDetails &others)
{
    for (const auto &other: others.details)
        mergeOne(*other);
}

SBuf
ErrorDetails::brief() const
{
    SBuf buf;
    for (const auto &detail: details) {
        if (buf.length())
            buf.append('+');
        buf.append(detail->brief());
    }
    return buf;
}

SBuf
ErrorDetails::verbose(const HttpRequestPointer &request) const
{
    SBuf buf;
    for (const auto &detail: details) {
        if (buf.length()) {
            static const SBuf delimiter("; ");
            buf.append(delimiter);
        }
        buf.append(detail->verbose(request));
    }
    return buf;
}

