
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
 * Copyright (c) 2003  Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "stmem.h"
#include "mem_node.h"
#include "Generic.h"

#if HAVE_IOSTREAM
#include <iostream>
#endif

void
testLowAndHigh()
{
    mem_hdr aHeader;
    assert (aHeader.lowestOffset() == 0);
    assert (aHeader.write (StoreIOBuffer()));
    assert (aHeader.lowestOffset() == 0);
    assert (aHeader.write (StoreIOBuffer(0, 1, NULL)));
    assert (aHeader.lowestOffset() == 0);
    char * sampleData = xstrdup ("A");
    assert (aHeader.write (StoreIOBuffer(1, 100, sampleData)));
    safe_free (sampleData);
    assert (aHeader.lowestOffset() == 100);
    assert (aHeader.endOffset() == 101);
    sampleData = xstrdup ("B");
    assert (aHeader.write (StoreIOBuffer(1, 10, sampleData)));
    safe_free (sampleData);
    assert (aHeader.lowestOffset() == 10);
    assert (aHeader.endOffset() == 101);
    assert (aHeader.hasContigousContentRange(Range<int64_t>(10,11)));
    assert (!aHeader.hasContigousContentRange(Range<int64_t>(10,12)));
    assert (!aHeader.hasContigousContentRange(Range<int64_t>(10,101)));
}

void
testSplayOfNodes()
{
    Splay<mem_node *> aSplay;
    mem_node *temp5;
    temp5 = new mem_node(5);
    temp5->nodeBuffer.length = 10;
    aSplay.insert (temp5, mem_hdr::NodeCompare);
    assert (aSplay.start()->data == temp5);
    assert (aSplay.finish()->data == temp5);

    mem_node *temp0;
    temp0 = new mem_node(0);
    temp0->nodeBuffer.length = 5;
    aSplay.insert (temp0, mem_hdr::NodeCompare);
    assert (aSplay.start()->data == temp0);
    assert (aSplay.finish()->data == temp5);

    mem_node *temp14;
    temp14 = new mem_node (14);
    temp14->nodeBuffer.length = 1;
    assert (aSplay.find(temp14,mem_hdr::NodeCompare));
    delete temp14;

    mem_node ref13  (13);
    assert (!aSplay.find(&ref13,mem_hdr::NodeCompare));
    ref13.nodeBuffer.length = 1;
    assert (aSplay.find(&ref13,mem_hdr::NodeCompare));
    aSplay.destroy(SplayNode<mem_node *>::DefaultFree);
}

void
testHdrVisit()
{
    mem_hdr aHeader;
    char * sampleData = xstrdup ("A");
    assert (aHeader.write (StoreIOBuffer(1, 100, sampleData)));
    safe_free (sampleData);
    sampleData = xstrdup ("B");
    assert (aHeader.write (StoreIOBuffer(1, 102, sampleData)));
    safe_free (sampleData);
    std::ostringstream result;
    PointerPrinter<mem_node *> foo(result, "\n");
    for_each (aHeader.getNodes().end(), aHeader.getNodes().end(), foo);
    for_each (aHeader.getNodes().begin(), aHeader.getNodes().begin(), foo);
    for_each (aHeader.getNodes().begin(), aHeader.getNodes().end(), foo);
    std::ostringstream expectedResult;
    expectedResult << "[100,101)" << std::endl << "[102,103)" << std::endl;
    assert (result.str() == expectedResult.str());
}

int
main(int argc, char **argv)
{
    assert (mem_node::InUseCount() == 0);
    testLowAndHigh();
    assert (mem_node::InUseCount() == 0);
    testSplayOfNodes();
    assert (mem_node::InUseCount() == 0);
    testHdrVisit();
    assert (mem_node::InUseCount() == 0);
    return 0;
}
