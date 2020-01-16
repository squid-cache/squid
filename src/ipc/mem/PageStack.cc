/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"

#include "base/TextException.h"
#include "Debug.h"
#include "ipc/mem/Page.h"
#include "ipc/mem/PageStack.h"

/// used to mark a stack slot available for storing free page offsets
const Ipc::Mem::PageStack::Value Writable = 0;

Ipc::Mem::PageStack::PageStack(const uint32_t aPoolId, const unsigned int aCapacity, const size_t aPageSize):
    thePoolId(aPoolId), theCapacity(aCapacity), thePageSize(aPageSize),
    theSize(theCapacity),
    theLastReadable(prev(theSize)), theFirstWritable(next(theLastReadable)),
    theItems(aCapacity)
{
    // initially, all pages are free
    for (Offset i = 0; i < theSize; ++i)
        theItems[i] = i + 1; // skip page number zero to keep numbers positive
}

/*
 * TODO: We currently rely on the theLastReadable hint during each
 * loop iteration. We could also use hint just for the start position:
 * (const Offset start = theLastReadable) and then scan the stack
 * sequentially regardless of theLastReadable changes by others. Which
 * approach is better? Same for push().
 */
bool
Ipc::Mem::PageStack::pop(PageId &page)
{
    Must(!page);

    // we may fail to dequeue, but be conservative to prevent long searches
    --theSize;

    // find a Readable slot, starting with theLastReadable and going left
    while (theSize >= 0) {
        Offset idx = theLastReadable;
        // mark the slot at ids Writable while extracting its current value
        const Value value = theItems[idx].fetch_and(0); // works if Writable is 0
        const bool popped = value != Writable;
        // theItems[idx] is probably not Readable [any more]

        // Whether we popped a Readable value or not, we should try going left
        // to maintain the index (and make progress).
        // We may fail if others already updated the index, but that is OK.
        theLastReadable.compare_exchange_weak(idx, prev(idx)); // may fail or lie

        if (popped) {
            // the slot we emptied may already be filled, but that is OK
            theFirstWritable = idx; // may lie
            page.pool = thePoolId;
            page.number = value;
            debugs(54, 9, page << " at " << idx << " size: " << theSize);
            return true;
        }
        // TODO: report suspiciously long loops
    }

    ++theSize;
    return false;
}

void
Ipc::Mem::PageStack::push(PageId &page)
{
    debugs(54, 9, page);

    if (!page)
        return;

    Must(pageIdIsValid(page));
    // find a Writable slot, starting with theFirstWritable and going right
    while (theSize < theCapacity) {
        Offset idx = theFirstWritable;
        auto isWritable = Writable;
        const bool pushed = theItems[idx].compare_exchange_strong(isWritable, page.number);
        // theItems[idx] is probably not Writable [any more];

        // Whether we pushed the page number or not, we should try going right
        // to maintain the index (and make progress).
        // We may fail if others already updated the index, but that is OK.
        theFirstWritable.compare_exchange_weak(idx, next(idx)); // may fail or lie

        if (pushed) {
            // the enqueued value may already by gone, but that is OK
            theLastReadable = idx; // may lie
            ++theSize;
            debugs(54, 9, page << " at " << idx << " size: " << theSize);
            page = PageId();
            return;
        }
        // TODO: report suspiciously long loops
    }
    Must(false); // the number of pages cannot exceed theCapacity
}

bool
Ipc::Mem::PageStack::pageIdIsValid(const PageId &page) const
{
    return page.pool == thePoolId && page.number != Writable &&
           page.number <= capacity();
}

size_t
Ipc::Mem::PageStack::sharedMemorySize() const
{
    return SharedMemorySize(thePoolId, theCapacity, thePageSize);
}

size_t
Ipc::Mem::PageStack::SharedMemorySize(const uint32_t, const unsigned int capacity, const size_t pageSize)
{
    const auto levelsSize = PageId::maxPurpose * sizeof(Levels_t);
    const size_t pagesDataSize = capacity * pageSize;
    return StackSize(capacity) + LevelsPaddingSize(capacity) + levelsSize + pagesDataSize;
}

size_t
Ipc::Mem::PageStack::StackSize(const unsigned int capacity)
{
    return sizeof(PageStack) + capacity * sizeof(Item);
}

size_t
Ipc::Mem::PageStack::stackSize() const
{
    return StackSize(theCapacity);
}

size_t
Ipc::Mem::PageStack::LevelsPaddingSize(const unsigned int capacity)
{
    const auto displacement = StackSize(capacity) % alignof(Levels_t);
    return displacement ? alignof(Levels_t) - displacement : 0;
}

