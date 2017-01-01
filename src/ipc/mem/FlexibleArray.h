/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_MEM_FLEXIBLE_ARRAY_H
#define SQUID_IPC_MEM_FLEXIBLE_ARRAY_H

// sometimes required for placement-new operator to be declared
#include <new>

namespace Ipc
{

namespace Mem
{

/// A "flexible array" of Items inside some shared memory space.
/// A portable equivalent of a "Item items[];" data member.
/// Some compilers such as Clang can only handle flexible arrays of PODs,
/// and the current C++ standard does not allow flexible arrays at all.
template <class Item>
class FlexibleArray
{
public:
    explicit FlexibleArray(const int capacity) {
        if (capacity > 1) // the first item is initialized automatically
            new (raw()+1) Item[capacity-1];
    }

    Item &operator [](const int idx) { return items[idx]; }
    const Item &operator [](const int idx) const { return items[idx]; }

    //const Item *operator ()() const { return items; }
    //Item *operator ()() { return items; }

    Item *raw() { return items; }

private:
    Item items[1]; // ensures proper alignment of array elements
};

} // namespace Mem

} // namespace Ipc

#endif /* SQUID_IPC_MEM_FLEXIBLE_ARRAY_H */

