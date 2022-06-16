/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_STORE_SWAPMETAOUT_H
#define SQUID_SRC_STORE_SWAPMETAOUT_H

#include "store/forward.h"

namespace Store {

/// swap metadata prefix and all swap metadata fields of the given entry
/// \param size gets filled with the total swap metadata size
const char *PackSwapMeta(const StoreEntry &, size_t &size);

} // namespace Store

#endif /* SQUID_SRC_STORE_SWAPMETAOUT_H */

