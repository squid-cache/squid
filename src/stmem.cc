/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 19    Store Memory Primitives */

#include "squid.h"
#include "Generic.h"
#include "mem_node.h"
#include "MemObject.h"
#include "profiler/Profiler.h"
#include "stmem.h"

/*
 * NodeGet() is called to get the data buffer to pass to storeIOWrite().
 * By setting the write_pending flag here we are assuming that there
 * will be no other users of NodeGet().  The storeIOWrite() callback
 * is memNodeWriteComplete(), which, for whatever reason, lives in
 * mem_node.cc.
 */
char *
mem_hdr::NodeGet(mem_node * aNode)
{
    assert(!aNode->write_pending);
    aNode->write_pending = true;
    return aNode->data;
}

int64_t
mem_hdr::lowestOffset () const
{
    const SplayNode<mem_node *> *theStart = nodes.start();

    if (theStart)
        return theStart->data->nodeBuffer.offset;

    return 0;
}

int64_t
mem_hdr::endOffset () const
{
    int64_t result = 0;
    const SplayNode<mem_node *> *theEnd = nodes.finish();

    if (theEnd)
        result = theEnd->data->dataRange().end;

    assert (result == inmem_hi);

    return result;
}

void
mem_hdr::freeContent()
{
    nodes.destroy();
    inmem_hi = 0;
    debugs(19, 9, HERE << this << " hi: " << inmem_hi);
}

bool
mem_hdr::unlink(mem_node *aNode)
{
    if (aNode->write_pending) {
        debugs(0, DBG_CRITICAL, "cannot unlink mem_node " << aNode << " while write_pending");
        return false;
    }

    debugs(19, 8, this << " removing " << aNode);
    nodes.remove (aNode, NodeCompare);
    delete aNode;
    return true;
}

int64_t
mem_hdr::freeDataUpto(int64_t target_offset)
{
    debugs(19, 8, this << " up to " << target_offset);
    /* keep the last one to avoid change to other part of code */
    SplayNode<mem_node*> const * theStart;

    while ((theStart = nodes.start())) {
        if (theStart == nodes.finish())
            break;

        if (theStart->data->end() > target_offset )
            break;

        if (!unlink(theStart->data))
            break;
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
mem_hdr::writeAvailable(mem_node *aNode, int64_t location, size_t amount, char const *source)
{
    /* if we attempt to overwrite existing data or leave a gap within a node */
    assert (location == aNode->nodeBuffer.offset + (int64_t)aNode->nodeBuffer.length);
    /* And we are not at the end of the node */
    assert (aNode->canAccept (location));

    /* these two can go I think */
    assert (location - aNode->nodeBuffer.offset == (int64_t)aNode->nodeBuffer.length);
    size_t copyLen = min(amount, aNode->space());

    memcpy(aNode->nodeBuffer.data + aNode->nodeBuffer.length, source, copyLen);

    debugs(19, 9, HERE << this << " hi: " << inmem_hi);
    if (inmem_hi <= location)
        inmem_hi = location + copyLen;

    /* Adjust the ptr and len according to what was deposited in the page */
    aNode->nodeBuffer.length += copyLen;

    debugs(19, 9, HERE << this << " hi: " << inmem_hi);
    debugs(19, 9, HERE << this << " hi: " << endOffset());
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
    debugs(19, 6, "memInternalAppend: " << this << " len " << len);

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
mem_hdr::getBlockContainingLocation (int64_t location) const
{
    // Optimize: do not create a whole mem_node just to store location
    mem_node target (location);
    target.nodeBuffer.length = 1;
    mem_node *const *result = nodes.find (&target, NodeCompare);

    if (result)
        return *result;

    return NULL;
}

size_t
mem_hdr::copyAvailable(mem_node *aNode, int64_t location, size_t amount, char *target) const
{
    if (aNode->nodeBuffer.offset > location)
        return 0;

    assert (aNode->nodeBuffer.offset <= location);

    assert (aNode->end() > location);

    size_t copyOffset = location - aNode->nodeBuffer.offset;

    size_t copyLen = min(amount, aNode->nodeBuffer.length - copyOffset);

    memcpy(target, aNode->nodeBuffer.data + copyOffset, copyLen);

    return copyLen;
}

void
mem_hdr::debugDump() const
{
    debugs (19, 0, "mem_hdr::debugDump: lowest offset: " << lowestOffset() << " highest offset + 1: " << endOffset() << ".");
    std::ostringstream result;
    PointerPrinter<mem_node *> foo(result, " - ");
    getNodes().visit(foo);
    debugs (19, 0, "mem_hdr::debugDump: Current available data is: " << result.str() << ".");
}

/* FIXME: how do we deal with sparse results -
 * where we have (say)
 * 0-500 and 1000-1500, but are asked for
 * 0-2000
 * Partial answer:
 * we supply 0-500 and stop.
 */
ssize_t
mem_hdr::copy(StoreIOBuffer const &target) const
{

    assert(target.range().end > target.range().start);
    debugs(19, 6, "memCopy: " << this << " " << target.range());

    /* we shouldn't ever ask for absent offsets */

    if (nodes.size() == 0) {
        debugs(19, DBG_IMPORTANT, "mem_hdr::copy: No data to read");
        debugDump();
        assert (0);
        return 0;
    }

    /* RC: the next assert is nearly useless */
    assert(target.length > 0);

    /* Seek our way into store */
    mem_node *p = getBlockContainingLocation(target.offset);

    if (!p) {
        debugs(19, DBG_IMPORTANT, "memCopy: could not find start of " << target.range() <<
               " in memory.");
        debugDump();
        fatal_dump("Squid has attempted to read data from memory that is not present. This is an indication of of (pre-3.0) code that hasn't been updated to deal with sparse objects in memory. Squid should coredump.allowing to review the cause. Immediately preceding this message is a dump of the available data in the format [start,end). The [ means from the value, the ) means up to the value. I.e. [1,5) means that there are 4 bytes of data, at offsets 1,2,3,4.\n");
        return 0;
    }

    size_t bytes_to_go = target.length;
    char *ptr_to_buf = target.data;
    int64_t location = target.offset;

    /* Start copying begining with this block until
     * we're satiated */

    while (p && bytes_to_go > 0) {
        size_t bytes_to_copy = copyAvailable (p,
                                              location, bytes_to_go, ptr_to_buf);

        /* hit a sparse patch */

        if (bytes_to_copy == 0)
            return target.length - bytes_to_go;

        location += bytes_to_copy;

        ptr_to_buf += bytes_to_copy;

        bytes_to_go -= bytes_to_copy;

        p = getBlockContainingLocation(location);
    }

    return target.length - bytes_to_go;
}

bool
mem_hdr::hasContigousContentRange(Range<int64_t> const & range) const
{
    int64_t currentStart = range.start;

    while (mem_node *curr = getBlockContainingLocation(currentStart)) {
        currentStart = curr->end();

        if (currentStart >= range.end)
            return true;
    }

    return !range.size(); // empty range is contigous
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
mem_hdr::nodeToRecieve(int64_t offset)
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
    debugs(19, 6, "mem_hdr::write: " << this << " " << writeBuffer.range() << " object end " << endOffset());

    if (unionNotEmpty(writeBuffer)) {
        debugs(19, DBG_CRITICAL, "mem_hdr::write: writeBuffer: " << writeBuffer.range());
        debugDump();
        fatal_dump("Attempt to overwrite already in-memory data. Preceding this there should be a mem_hdr::write output that lists the attempted write, and the currently present data. Please get a 'backtrace full' from this error - using the generated core, and file a bug report with the squid developers including the last 10 lines of cache.log and the backtrace.\n");
        PROF_stop(mem_hdr_write);
        return false;
    }

    assert (writeBuffer.offset >= 0);

    mem_node *target;
    int64_t currentOffset = writeBuffer.offset;
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
{
    debugs(19, 9, HERE << this << " hi: " << inmem_hi);
}

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
    debugs(20, DBG_IMPORTANT, "mem_hdr: " << (void *)this << " nodes.start() " << nodes.start());
    debugs(20, DBG_IMPORTANT, "mem_hdr: " << (void *)this << " nodes.finish() " << nodes.finish());
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

