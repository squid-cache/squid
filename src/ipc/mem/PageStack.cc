/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"

#include "base/TextException.h"
#include "ipc/mem/PageStack.h"

/// used to mark a stack slot available for storing free page offsets
const Ipc::Mem::PageStack::Value Writable = 0;


Ipc::Mem::PageStack::PageStack(const String &id, const unsigned int capacity):
    shm(id.termedBuf())
{
    const size_t mySharedSize = Shared::MemSize(capacity);
    shm.create(mySharedSize);
    assert(shm.mem());
    shared = new (shm.reserve(mySharedSize)) Shared(capacity);
}

Ipc::Mem::PageStack::PageStack(const String &id): shm(id.termedBuf())
{
    shm.open();
    shared = reinterpret_cast<Shared *>(shm.mem());
    assert(shared);
    const off_t mySharedSize = Shared::MemSize(shared->theCapacity);
    assert(shared == reinterpret_cast<Shared *>(shm.reserve(mySharedSize)));
}

void
Ipc::Mem::PageStack::Unlink(const String &id)
{
    Segment::Unlink(id.termedBuf());
}

/*
 * TODO: We currently rely on the theLastReadable hint during each
 * loop iteration. We could also use hint just for the start position:
 * (const Offset start = theLastReadable) and then scan the stack
 * sequentially regardless of theLastReadable changes by others. Which
 * approach is better? Same for push().
 */
bool
Ipc::Mem::PageStack::pop(Value &value)
{
    // we may fail to dequeue, but be conservative to prevent long searches
    --shared->theSize;

    // find a Readable slot, starting with theLastReadable and going left
    while (shared->theSize >= 0) {
        const Offset idx = shared->theLastReadable;
        // mark the slot at ids Writable while extracting its current value
        value = shared->theItems[idx].fetchAndAnd(0); // works if Writable is 0
        const bool popped = value != Writable;
        // theItems[idx] is probably not Readable [any more]

        // Whether we popped a Readable value or not, we should try going left
        // to maintain the index (and make progress).
        // We may fail if others already updated the index, but that is OK.
        shared->theLastReadable.swap_if(idx, shared->prev(idx)); // may fail or lie

        if (popped) {
            // the slot we emptied may already be filled, but that is OK
            shared->theFirstWritable = idx; // may lie
            return true;
        }
        // TODO: report suspiciously long loops
    }

    ++shared->theSize;
    return false;
}

void
Ipc::Mem::PageStack::push(const Value value)
{
    Must(value != Writable);
    Must(static_cast<Offset>(value) <= shared->theCapacity);
    // find a Writable slot, starting with theFirstWritable and going right
    while (shared->theSize < shared->theCapacity) {
        const Offset idx = shared->theFirstWritable;
        const bool pushed = shared->theItems[idx].swap_if(Writable, value);
        // theItems[idx] is probably not Writable [any more];

        // Whether we pushed the value or not, we should try going right
        // to maintain the index (and make progress).
        // We may fail if others already updated the index, but that is OK.
        shared->theFirstWritable.swap_if(idx, shared->next(idx)); // may fail or lie

        if (pushed) {
            // the enqueued value may already by gone, but that is OK
            shared->theLastReadable = idx; // may lie
            ++shared->theSize;
            return;
        }
        // TODO: report suspiciously long loops
    }
    Must(false); // the number of pages cannot exceed theCapacity
}

Ipc::Mem::PageStack::Shared::Shared(const unsigned int aCapacity):
    theCapacity(aCapacity), theSize(theCapacity),
    theLastReadable(prev(theSize)), theFirstWritable(next(theLastReadable))
{
    // initially, all pages are free
    for (Offset i = 0; i < theSize; ++i)
        theItems[i] = i + 1; // skip page number zero to keep numbers positive
}

size_t
Ipc::Mem::PageStack::Shared::MemSize(const unsigned int capacity)
{
    return sizeof(Item) * capacity + sizeof(Shared);
}
