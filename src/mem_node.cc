/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 19    Store Memory Primitives */

#include "squid.h"
#include "mem/Pool.h"
#include "mem_node.h"

static ptrdiff_t makeMemNodeDataOffset();

static ptrdiff_t _mem_node_data_offset = makeMemNodeDataOffset();

/*
 * Calculate the offset between the start of a mem_node and
 * its 'data' member
 */
static ptrdiff_t
makeMemNodeDataOffset()
{
    mem_node *p = 0L;
    return ptrdiff_t(&p->data);
}

/*
 * This is the callback when storeIOWrite() is done.  We need to
 * clear the write_pending flag for the mem_node.  First we have
 * to calculate the start of the mem_node based on the character
 * buffer that we wrote.  ick.
 */
void
memNodeWriteComplete(void* d)
{
    mem_node* n = (mem_node*)((char*)d - _mem_node_data_offset);
    assert(n->write_pending);
    n->write_pending = false;
}

mem_node::mem_node(int64_t offset) :
    nodeBuffer(0,offset,data),
    write_pending(false)
{
    *data = 0;
}

mem_node::~mem_node()
{}

size_t
mem_node::InUseCount()
{
    return Pool().inUseCount();
}

size_t
mem_node::StoreMemSize()
{
    return InUseCount() * SM_PAGE_SIZE;
}

int64_t
mem_node::start() const
{
    assert (nodeBuffer.offset >= 0);
    return nodeBuffer.offset;
}

int64_t
mem_node::end() const
{
    return nodeBuffer.offset + nodeBuffer.length;
}

Range<int64_t>
mem_node::dataRange() const
{
    return Range<int64_t> (start(), end());
}

size_t
mem_node::space() const
{
    return SM_PAGE_SIZE - nodeBuffer.length;
}

bool
mem_node::contains (int64_t const &location) const
{
    if (start() <= location && end() > location)
        return true;

    return false;
}

/* nodes can not be sparse */
bool
mem_node::canAccept (int64_t const &location) const
{
    if (location == end() && space() > 0)
        return true;

    return false;
}

bool
mem_node::operator < (mem_node const & rhs) const
{
    return start() < rhs.start();
}

