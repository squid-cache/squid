/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_ASYNCCALLLIST_H
#define SQUID_SRC_BASE_ASYNCCALLLIST_H

#include "base/forward.h"
#include "base/RefCount.h"

/// An efficient (but intrusive) AsyncCall storage preserving FIFO order.
/// A given AsyncCall object may reside in at most one such storage.
class AsyncCallList
{
public:
    AsyncCallList() = default;
    // prohibit copying: no AsyncCall should be present in two lists
    AsyncCallList(const AsyncCallList &) = delete;
    AsyncCallList &operator=(const AsyncCallList &) = delete;

    /// stores the given async call
    void add(const AsyncCallPointer &);

    /// removes the earliest add()-ed call that is still stored (if any)
    /// \returns the removed call (or nil)
    /// \retval nil means the list stored no calls at extract() time
    AsyncCallPointer extract();

    /// the number of currently stored calls
    size_t size() const { return length; }

private:
    AsyncCallPointer head; ///< the earliest still-stored call (or nil)
    AsyncCallPointer tail; ///< the latest still-stored call (or nil)
    size_t length = 0; ///< \copydoc size()
};

#endif /* SQUID_SRC_BASE_ASYNCCALLLIST_H */

