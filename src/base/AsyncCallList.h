/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ASYNCCALLLIST_H
#define SQUID_ASYNCCALLLIST_H

#include "base/forward.h"
#include "base/RefCount.h"

/// AsyncCall FIFO storage
class AsyncCallList
{
public:
    /// appends the back element to the list
    void add(const AsyncCallPointer &);
    /// removes and returns front element of the list
    AsyncCallPointer extract();
    /// the list length
    size_t size() const { return length; }

private:
    AsyncCallPointer head;
    AsyncCallPointer tail;
    size_t length = 0;
};

#endif /* SQUID_ASYNCCALLLIST_H */

