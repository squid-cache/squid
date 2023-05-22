/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_MEM_FLEXIBLE_ARRAY_H
#define SQUID_IPC_MEM_FLEXIBLE_ARRAY_H

#include <cstddef>
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
        new (raw()) Item[capacity];
    }

    Item &operator [](const int idx) { return *(raw() + idx); }

    Item *raw() { return reinterpret_cast<Item*>(&start_); }

private:
    alignas(Item) std::byte start_; ///< the first byte of the first array item
};

} // namespace Mem

} // namespace Ipc

#endif /* SQUID_IPC_MEM_FLEXIBLE_ARRAY_H */

