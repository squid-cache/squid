
/*
 * $Id$
 *
 * DEBUG: section 19    Store Memory Primitives
 * AUTHOR: Robert Collins
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
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
    n->write_pending = 0;
}

mem_node::mem_node(int64_t offset):nodeBuffer(0,offset,data)
{}

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
