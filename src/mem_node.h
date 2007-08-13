
/*
 * $Id: mem_node.h,v 1.10 2007/08/13 17:20:51 hno Exp $
 *
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

#ifndef SQUID_MEM_NODE_H
#define SQUID_MEM_NODE_H

#include "StoreIOBuffer.h"
#include "Range.h"

class mem_node
{

public:
    static size_t InUseCount();
    static unsigned long store_mem_size;	/* 0 */

    MEMPROXY_CLASS(mem_node);
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

unsigned int write_pending:
    1;
};

MEMPROXY_CLASS_INLINE(mem_node)

inline std::ostream &
operator << (std::ostream &os, mem_node &aNode)
{
    os << aNode.nodeBuffer.range();
    return os;
}

void memNodeWriteComplete(void *);

#endif /* SQUID_MEM_NODE_H */
