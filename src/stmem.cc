
/*
 * $Id: stmem.cc,v 1.83 2003/09/29 10:24:01 robertc Exp $
 *
 * DEBUG: section 19    Store Memory Primitives
 * AUTHOR: Harvest Derived
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "stmem.h"
#include "mem_node.h"
#include "MemObject.h"
#include "Generic.h"

int
mem_hdr::lowestOffset () const
{
    const SplayNode<mem_node *> *theStart = nodes.start();

    if (theStart)
        return theStart->data->nodeBuffer.offset;

    return 0;
}

off_t
mem_hdr::endOffset () const
{
    off_t result = 0;
    const SplayNode<mem_node *> *theEnd = nodes.finish();

    if (theEnd)
        result = theEnd->data->dataRange().end;

    assert (result == inmem_hi);

    return result;
}

void
mem_hdr::freeContent()
{
    nodes.destroy(SplayNode<mem_node *>::DefaultFree);
    inmem_hi = 0;
}

void
mem_hdr::unlink(mem_node *aNode)
{
    nodes.remove (aNode, NodeCompare);
    delete aNode;
}

int
mem_hdr::freeDataUpto(int target_offset)
{
    /* keep the last one to avoid change to other part of code */

    SplayNode<mem_node*> const * theStart = nodes.start();

    while (theStart && theStart != nodes.finish() &&
            theStart->data->end() <= (size_t) target_offset ) {
        unlink(theStart->data);
        theStart = nodes.start();
    }

    assert (lowestOffset () <= target_offset);

    return lowestOffset ();
}

int
mem_hdr::appendToNode(mem_node *aNode, const char *data, int maxLength)
{
    size_t result = writeAvailable (aNode, aNode->nodeBuffer.offset + aNode->nodeBuffer.length ,maxLength, data);
    return result;
}

size_t
mem_hdr::writeAvailable(mem_node *aNode, size_t location, size_t amount, char const *source)
{
    /* if we attempt to overwrite existing data or leave a gap within a node */
    assert (location == aNode->nodeBuffer.offset + aNode->nodeBuffer.length);
    /* And we are not at the end of the node */
    assert (aNode->canAccept (location));

    /* these two can go I think */
    assert (location - aNode->nodeBuffer.offset == aNode->nodeBuffer.length);
    size_t copyLen = XMIN (amount, aNode->space());

    xmemcpy(aNode->nodeBuffer.data + aNode->nodeBuffer.length, source, copyLen);

    if (inmem_hi <= (off_t) location)
        inmem_hi = location + copyLen;

    /* Adjust the ptr and len according to what was deposited in the page */
    aNode->nodeBuffer.length += copyLen;

    mem_node::store_mem_size += copyLen;

    return copyLen;
}

void
mem_hdr::appendNode (mem_node *aNode)
{
    nodes.insert (aNode, NodeCompare);
}

void
mem_hdr::makeAppendSpace()
{
    if (!nodes.size()) {
        appendNode (new mem_node (0));
        return;
    }

    if (!nodes.finish()->data->space())
        appendNode (new mem_node (endOffset()));

    assert (nodes.finish()->data->space());
}

void
mem_hdr::internalAppend(const char *data, int len)
{
    debug(19, 6) ("memInternalAppend: len %d\n", len);

    while (len > 0) {
        makeAppendSpace();
        int copied = appendToNode (nodes.finish()->data, data, len);
        assert (copied);

        len -= copied;
        data += copied;
    }
}

/* returns a mem_node that contains location..
 * If no node contains the start, it returns NULL.
 */
mem_node *
mem_hdr::getBlockContainingLocation (size_t location) const
{
    mem_node target (location);
    target.nodeBuffer.length = 1;
    mem_node *const *result = nodes.find (&target, NodeCompare);

    if (result)
        return *result;

    return NULL;
}

size_t
mem_hdr::copyAvailable(mem_node *aNode, size_t location, size_t amount, char *target) const
{
    if (aNode->nodeBuffer.offset > (off_t) location)
        return 0;

    assert (aNode->nodeBuffer.offset <= (off_t) location);

    assert (aNode->end() > location);

    size_t copyOffset = location - aNode->nodeBuffer.offset;

    size_t copyLen = XMIN (amount, aNode->nodeBuffer.length - copyOffset);

    xmemcpy(target, aNode->nodeBuffer.data + copyOffset, copyLen);

    return copyLen;
}

void
mem_hdr::debugDump() const
{
    std::ostringstream result;
    PointerPrinter<mem_node *> foo(result, " - ");
    for_each (getNodes().begin(), getNodes().end(), foo);
    debugs (19, 1, "mem_hdr::debugDump: Current available data is: " << result.str() << ".");
}

/* FIXME: how do we deal with sparse results -
 * where we have (say)
 * 0-500 and 1000-1500, but are asked for 
 * 0-2000
 * Partial answer:
 * we supply 0-500 and stop.
 */
ssize_t
mem_hdr::copy(off_t offset, char *buf, size_t size) const
{

    debugs(19, 6, "memCopy: offset " << offset << ": size " <<  size);

    /* we shouldn't ever ask for absent offsets */

    if (nodes.size() == 0) {
        debugs(19, 1, "mem_hdr::copy: No data to read");
        debugDump();
        assert (0);
        return 0;
    }

    /* RC: the next assert is nearly useless */
    assert(size > 0);

    /* Seek our way into store */
    mem_node *p = getBlockContainingLocation((size_t)offset);

    if (!p) {
        debugs(19, 1, "memCopy: could not find offset " << offset <<
               " in memory.");
        debugDump();
        /* we shouldn't ever ask for absent offsets */
        assert (0);
        return 0;
    }

    size_t bytes_to_go = size;
    char *ptr_to_buf = buf;
    off_t location = offset;

    /* Start copying begining with this block until
     * we're satiated */

    while (p && bytes_to_go > 0) {
        size_t bytes_to_copy = copyAvailable (p,
                                              location, bytes_to_go, ptr_to_buf);

        /* hit a sparse patch */

        if (bytes_to_copy == 0)
            return size - bytes_to_go;

        location += bytes_to_copy;

        ptr_to_buf += bytes_to_copy;

        bytes_to_go -= bytes_to_copy;

        p = getBlockContainingLocation(location);
    }

    return size - bytes_to_go;
}

bool
mem_hdr::hasContigousContentRange(Range<size_t> const & range) const
{
    size_t currentStart = range.start;

    while (mem_node *curr = getBlockContainingLocation(currentStart)) {
        currentStart = curr->end();

        if (currentStart >= range.end)
            return true;
    }

    return false;
}

bool
mem_hdr::unionNotEmpty(StoreIOBuffer const &candidate)
{
    assert (candidate.offset >= 0);
    mem_node target(candidate.offset);
    target.nodeBuffer.length = candidate.length;
    return nodes.find (&target, NodeCompare);
}

mem_node *
mem_hdr::nodeToRecieve(off_t offset)
{
    /* case 1: Nothing in memory */

    if (!nodes.size()) {
        appendNode (new mem_node(offset));
        return nodes.start()->data;
    }

    mem_node *candidate = NULL;
    /* case 2: location fits within an extant node */

    if (offset > 0) {
        mem_node search (offset - 1);
        search.nodeBuffer.length = 1;
        mem_node *const *leadup =  nodes.find (&search, NodeCompare);

        if (leadup)
            candidate = *leadup;
    }

    if (candidate && candidate->canAccept(offset))
        return candidate;

    /* candidate can't accept, so we need a new node */
    candidate = new mem_node(offset);

    appendNode (candidate);

    /* simpler to write than a indented if */
    return candidate;
}


bool
mem_hdr::write (StoreIOBuffer const &writeBuffer)
{
    PROF_start(mem_hdr_write);
    //    mem_node *tempNode;
    debug(19, 6) ("mem_hdr::write: offset %lu len %ld, object end %lu\n", (unsigned long)writeBuffer.offset, (long)writeBuffer.length, (unsigned long)endOffset());

    if (unionNotEmpty(writeBuffer)) {
        fatal("Attempt to overwrite already in-memory data\n");
        PROF_stop(mem_hdr_write);
        return false;
    }

    assert (writeBuffer.offset >= 0);

    mem_node *target;
    off_t currentOffset = writeBuffer.offset;
    char *currentSource = writeBuffer.data;
    size_t len = writeBuffer.length;

    while (len && (target = nodeToRecieve(currentOffset))) {
        size_t wrote = writeAvailable(target, currentOffset, len, currentSource);
        assert (wrote);
        len -= wrote;
        currentOffset += wrote;
        currentSource += wrote;
    }

    PROF_stop(mem_hdr_write);
    return true;
}

mem_hdr::mem_hdr() : inmem_hi(0)
{}

mem_hdr::~mem_hdr()
{
    freeContent();
}

/* splay of mem nodes:
 * conditions:
 * a = b if a.intersection(b).size > 0;
 * a < b if a < b
 */
int
mem_hdr::NodeCompare(mem_node * const &left, mem_node * const &right)
{
    // possibly Range can help us at some point.

    if (left->dataRange().intersection(right->dataRange()).size() > 0)
        return 0;

    return *left < *right ? -1 : 1;
}

void
mem_hdr::dump() const
{
    debug(20, 1) ("mem_hdr: %p nodes.start() %p\n", this, nodes.start());
    debug(20, 1) ("mem_hdr: %p nodes.finish() %p\n", this, nodes.finish());
}

size_t
mem_hdr::size() const
{
    return nodes.size();
}

mem_node const *
mem_hdr::start() const
{
    const SplayNode<mem_node *> * result = nodes.start();

    if (result)
        return result->data;

    return NULL;
}

const Splay<mem_node *> &
mem_hdr::getNodes() const
{
    return nodes;
}
