
/*
 * $Id: mem_node.cc,v 1.4 2003/06/26 12:51:57 robertc Exp $
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

MemPool *mem_node::pool = NULL;
unsigned long mem_node::store_mem_size;

void *
mem_node::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (mem_node));

    if (!pool)
        pool = memPoolCreate("mem_node", sizeof (mem_node));

    return memPoolAlloc(pool);
}

void
mem_node::operator delete (void *address)
{
    memPoolFree(pool, address);
}

void
mem_node::deleteSelf() const
{
    delete this;
}

mem_node::mem_node(off_t offset):nodeBuffer(0,offset,data)
{}

mem_node::~mem_node()
{
    store_mem_size -= nodeBuffer.length;
}

size_t
mem_node::InUseCount()
{
    if (!pool)
        return 0;

    MemPoolStats stats;

    memPoolGetStats (&stats, pool);

    return stats.items_inuse;
}

size_t
mem_node::start() const
{
    assert (nodeBuffer.offset >= 0);
    return nodeBuffer.offset;
}

size_t
mem_node::end() const
{
    return nodeBuffer.offset + nodeBuffer.length;
}

Range<size_t>
mem_node::dataRange() const
{
    return Range<size_t> (start(), end());
}

size_t
mem_node::space() const
{
    return SM_PAGE_SIZE - nodeBuffer.length;
}

bool
mem_node::contains (size_t const &location) const
{
    if (start() <= location && end() > location)
        return true;

    return false;
}

/* nodes can not be sparse */
bool
mem_node::canAccept (size_t const &location) const
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
