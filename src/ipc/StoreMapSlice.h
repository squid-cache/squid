#ifndef SQUID_IPC_STORE_MAP_SLICE_H
#define SQUID_IPC_STORE_MAP_SLICE_H

#include "typedefs.h"

namespace Ipc
{

typedef uint32_t StoreMapSliceId;

/// a piece of Store entry, linked to other pieces, forming a chain
class StoreMapSlice
{
public:
    StoreMapSlice(): next(0), /* location(0), */ size(0) {}

    StoreMapSliceId next; ///< ID of the next slice occupied by the entry
//    uint32_t location; ///< slice contents location
    uint32_t size; ///< slice contents size
};

} // namespace Ipc

#endif /* SQUID_IPC_STORE_MAP_SLICE_H */
