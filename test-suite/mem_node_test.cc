
/*
 * $Id: mem_node_test.cc,v 1.6 2004/08/30 03:29:03 robertc Exp $
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
#include <iostream>

/* TODO: put this in a libTest */
void
xassert(const char *msg, const char *file, int line)
{
    std::cout << "Assertion failed: (" << msg << ") at " << file << ":" << line << std::endl;
    exit (1);
}

int
main (int argc, char *argv)
{
    mem_node *aNode = new mem_node(0);
    assert (aNode);
    /* This will fail if MemPools are disabled. A knock on effect is that
     * the store will never trim memory
     */
    assert (mem_node::InUseCount() == 1);
    assert (SM_PAGE_SIZE > 50);
    aNode->nodeBuffer.length = 45;
    assert (aNode->start() == 0);
    assert (aNode->end() == 45);
    assert (aNode->dataRange().size() == 45);
    aNode->nodeBuffer.offset = 50;
    assert (aNode->start() == 50);
    assert (aNode->end() == 95);
    assert (aNode->dataRange().size() == 45);
    assert (!aNode->contains(49));
    assert (aNode->contains(50));
    assert (aNode->contains(75));
    assert (!aNode->contains(95));
    assert (aNode->contains(94));
    assert (!aNode->canAccept(50));
    assert (aNode->canAccept(95));
    assert (!aNode->canAccept(94));
    aNode->nodeBuffer.length = SM_PAGE_SIZE - 1;
    assert (aNode->canAccept (50 + SM_PAGE_SIZE - 1));
    assert (!aNode->canAccept (50 + SM_PAGE_SIZE));
    assert (mem_node (0) < mem_node (2));
    assert (!(mem_node (0) < mem_node (0)));
    assert (!(mem_node (2) < mem_node (0)));
    delete aNode;
    assert (mem_node::InUseCount() == 0);
    return 0;
}
