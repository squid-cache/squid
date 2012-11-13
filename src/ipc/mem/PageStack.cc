/*
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "squid.h"

#include "base/TextException.h"
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
        const Offset idx = theLastReadable;
        // mark the slot at ids Writable while extracting its current value
        const Value value = theItems[idx].fetchAndAnd(0); // works if Writable is 0
        const bool popped = value != Writable;
        // theItems[idx] is probably not Readable [any more]

        // Whether we popped a Readable value or not, we should try going left
        // to maintain the index (and make progress).
        // We may fail if others already updated the index, but that is OK.
        theLastReadable.swap_if(idx, prev(idx)); // may fail or lie

        if (popped) {
            // the slot we emptied may already be filled, but that is OK
            theFirstWritable = idx; // may lie
            page.pool = thePoolId;
            page.number = value;
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
    if (!page)
        return;

    Must(pageIdIsValid(page));
    // find a Writable slot, starting with theFirstWritable and going right
    while (theSize < theCapacity) {
        const Offset idx = theFirstWritable;
        const bool pushed = theItems[idx].swap_if(Writable, page.number);
        // theItems[idx] is probably not Writable [any more];

        // Whether we pushed the page number or not, we should try going right
        // to maintain the index (and make progress).
        // We may fail if others already updated the index, but that is OK.
        theFirstWritable.swap_if(idx, next(idx)); // may fail or lie

        if (pushed) {
            // the enqueued value may already by gone, but that is OK
            theLastReadable = idx; // may lie
            ++theSize;
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
    const size_t levelsSize = PageId::maxPurpose * sizeof(Atomic::Word);
    const size_t pagesDataSize = capacity * pageSize;
    return StackSize(capacity) + pagesDataSize + levelsSize;
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
