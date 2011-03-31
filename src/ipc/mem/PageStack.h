/*
 * $Id$
 *
 */

#ifndef SQUID_IPC_MEM_PAGE_STACK_H
#define SQUID_IPC_MEM_PAGE_STACK_H

#include "ipc/AtomicWord.h"
#include "ipc/SharedMemory.h"

namespace Ipc {

namespace Mem {

/// Atomic container of "free" page numbers inside a single SharedMemory space.
/// Assumptions: all page numbers are unique, positive, have an known maximum,
/// and can be temporary unavailable as long as they are never trully lost.
class PageStack {
public:
    typedef uint32_t Value; ///< stack item type (a free page number)

    /// creates a new shared stack that can hold up to capacity items
    PageStack(const String &id, const unsigned int capacity);
    /// attaches to the identified shared stack
    PageStack(const String &id);

    /// sets value and returns true unless no free page numbers are found
    bool pop(Value &value);
    /// makes value available as a free page number to future pop() callers
    void push(const Value value);

private:
    typedef unsigned int Offset; ///< stack index type

    struct Shared {
        Shared(const unsigned int theCapacity);

        // these help iterate the stack in search of a free spot or a page
        Offset next(const Offset idx) const { return (idx + 1) % theCapacity; }
        Offset prev(const Offset idx) const { return (theCapacity + idx - 1) % theCapacity; }

        const Offset theCapacity; ///< stack capacity, i.e. theItems size
        /// lower bound for the number of free pages (may get negative!)
        AtomicWordT<Offset> theSize;

        /// last readable item index; just a hint, not a guarantee
        AtomicWordT<Offset> theLastReadable;
        /// first writable item index; just a hint, not a guarantee
        AtomicWordT<Offset> theFirstWritable;

        typedef AtomicWordT<Value> Item;
        Item theItems[]; ///< page number storage
    };

    SharedMemory shm; ///< shared memory segment to store metadata (and pages)
    Shared *shared; ///< our metadata, shared among all stack users
};

} // namespace Mem

} // namespace Ipc

#endif // SQUID_IPC_MEM_PAGE_STACK_H
