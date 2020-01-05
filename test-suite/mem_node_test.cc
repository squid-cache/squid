/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 19    Store Memory Primitives */

#include "squid.h"
#include "mem_node.h"

#include <iostream>

int
main(int, char *[])
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
    return EXIT_SUCCESS;
}

