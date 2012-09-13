/*
 */

#ifndef SQUID_IPC_STRAND_COORDS_H
#define SQUID_IPC_STRAND_COORDS_H

#include "ipc/StrandCoord.h"
#include <vector>

namespace Ipc
{

/// a collection of strand coordinates; the order, if any, is owner-dependent
typedef std::vector<StrandCoord> StrandCoords;

} // namespace Ipc

#endif /* SQUID_IPC_STRAND_COORDS_H */
