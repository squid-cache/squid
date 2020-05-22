/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_MEM_NODE_H
#define SQUID_MEM_NODE_H

#include "base/Range.h"
#include "defines.h"
#include "mem/forward.h"
#include "StoreIOBuffer.h"

class mem_node
{
    MEMPROXY_CLASS(mem_node);

public:
    static size_t InUseCount();
    static size_t StoreMemSize();

    mem_node(int64_t);
    ~mem_node();
    size_t space() const;
    int64_t start() const;
    int64_t end() const;
    Range<int64_t> dataRange() const;
    bool contains (int64_t const &location) const;
    bool canAccept (int64_t const &location) const;
    bool operator < (mem_node const & rhs) const;
    /* public */
    StoreIOBuffer nodeBuffer;
    /* Private */
    char data[SM_PAGE_SIZE];
    bool write_pending;
};

inline std::ostream &
operator << (std::ostream &os, mem_node &aNode)
{
    os << aNode.nodeBuffer.range();
    return os;
}

void memNodeWriteComplete(void *);

#endif /* SQUID_MEM_NODE_H */

