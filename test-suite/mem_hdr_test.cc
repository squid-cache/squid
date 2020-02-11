/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 19    Store Memory Primitives */

#include "squid.h"
#include "Generic.h"
#include "mem_node.h"
#include "stmem.h"

#include <iostream>
#include <sstream>

void
testLowAndHigh()
{
    mem_hdr aHeader;
    assert (aHeader.lowestOffset() == 0);
    assert (aHeader.write (StoreIOBuffer()));
    assert (aHeader.lowestOffset() == 0);
    assert (aHeader.write (StoreIOBuffer(0, 1, (char *)NULL)));
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
    aSplay.destroy();
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

