
/*
 * $Id: stmem.cc,v 1.74 2003/01/23 00:37:26 robertc Exp $
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
 */

#include "squid.h"
#include "stmem.h"
#include "mem_node.h"
#include "MemObject.h"

int
mem_hdr::lowestOffset () const
{
    if (head)
	return head->nodeBuffer.offset;
    return 0;
}

off_t
mem_hdr::endOffset () const
{
    off_t result = 0;
    if (tail)
	result = tail->nodeBuffer.offset + tail->nodeBuffer.length;
    assert (result == inmem_hi);
    return result;
}

void
mem_hdr::freeContent()
{
    while (head)
	unlinkHead();
    head = tail = NULL;
    inmem_hi = 0;
}

void
mem_hdr::unlinkHead()
{
    assert (head);
    mem_node *aNode = head;
    head = aNode->next;
    aNode->next = NULL;
    delete aNode;
}

int
mem_hdr::freeDataUpto(int target_offset)
{
    /* keep the last one to avoid change to other part of code */
    while (head && head != tail &&
	((lowestOffset() + head->nodeBuffer.length) <= (size_t)target_offset))
	unlinkHead ();
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
    size_t copyOffset = location - aNode->nodeBuffer.offset;
    assert (copyOffset == aNode->nodeBuffer.length);
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
    assert (aNode->next == NULL);
    if (!head) {
	/* The chain is empty */
	head = tail = aNode;
    } else {
	mem_node *pointer = getHighestBlockBeforeLocation(aNode->nodeBuffer.offset);
	if (!pointer) {
	    /* prepend to list */
	    aNode->next = head;
	    head = aNode->next;
	} else {
	    /* Append it to existing chain */
	    aNode->next = pointer->next;
	    pointer->next = aNode;
	    if (tail == pointer)
		tail = aNode;
	}
    }
}

void
mem_hdr::makeAppendSpace()
{
    if (!head) {
	appendNode (new mem_node(0));
	return;
    }
    if (!tail->space())
	appendNode (new mem_node (endOffset()));
    assert (tail->space());
}

void
mem_hdr::internalAppend(const char *data, int len)
{
    debug(19, 6) ("memInternalAppend: len %d\n", len);
    while (len > 0) {
	makeAppendSpace();

	int copied = appendToNode (tail, data, len);
	assert (copied);
	
	len -= copied;
	data += copied;
    }
}

mem_node *
mem_hdr::getHighestBlockBeforeLocation (size_t location) const
{
    mem_node *result = head;
    mem_node *prevResult = NULL;
    while (result && result->end() <= location) {
	if (!result->next)
	    return result;
	prevResult = result;
	result = result->next;
	if (result->contains(location))
	    return result;
    }
    /* the if here is so we catch 0 offset requests */
    if (result && result->contains(location))
	return result;
    else 
	return prevResult;
}

/* returns a mem_node that contains location..
 * If no node contains the start, it returns NULL.
 */
mem_node *
mem_hdr::getBlockContainingLocation (size_t location) const
{
    mem_node *result = getHighestBlockBeforeLocation(location);
    if (!result || !result->contains(location))
	return NULL;
    return result;
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

    debug(19, 6) ("memCopy: offset %ld: size %u\n", (long int) offset, size);
    if (head == NULL)
	return 0;
    /* RC: the next assert is nearly useless */
    assert(size > 0);

    /* Seek our way into store */
    mem_node *p = getBlockContainingLocation((size_t)offset);
    if (!p) {
	debug(19, 1) ("memCopy: could not find offset %u in memory.\n", (size_t) offset);
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
	p = p->next;
    }
    return size - bytes_to_go;
}

bool
mem_hdr::hasContigousContentRange(size_t start, size_t end) const
{
    size_t currentStart = start;
    while (mem_node *curr = getBlockContainingLocation(currentStart)) {
	currentStart = curr->end();
	if (currentStart >= end)
	    return true;
    }
    return false;
}

bool
mem_hdr::unionNotEmpty(StoreIOBuffer const &candidate)
{
    mem_node *low = getHighestBlockBeforeLocation(candidate.offset);
    assert (candidate.offset >= 0);
    if (low && low->end() > (size_t) candidate.offset)
	return true;
    mem_node *high = getHighestBlockBeforeLocation(candidate.offset + candidate.length);
    /* trivial case - we are writing completely beyond the end of the current object */
    if (low == high)
	return false;
    if (high && high->start() < candidate.offset + candidate.length &&
	!high->end() > candidate.offset)
	return true;
    return false;
}

mem_node *
mem_hdr::nodeToRecieve(off_t offset)
{
    /* case 1: Nothing in memory */
    if (!head) {
	appendNode (new mem_node(offset));
	return head;
    }

    /* case 2: location fits within an extant node */
    mem_node *candidate = getHighestBlockBeforeLocation(offset);
    /* case 2: no nodes before it */
    if (!candidate) {
	candidate = new mem_node(offset);
	appendNode (candidate);
	assert (candidate->canAccept(offset));
    }

    if (candidate->canAccept(offset))
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
//    mem_node *tempNode;
    debug(19, 6) ("mem_hdr::write: offset %lu len %d, object end %lu\n", writeBuffer.offset, writeBuffer.length, endOffset());

    if (unionNotEmpty(writeBuffer)) {
	fatal("Attempt to overwrite already in-memory data\n");
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

    return true;
}
