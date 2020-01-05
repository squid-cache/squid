/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
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

