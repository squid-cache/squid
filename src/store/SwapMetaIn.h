/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_STORE_SWAPMETAIN_H
#define SQUID_SRC_STORE_SWAPMETAIN_H

#include "sbuf/forward.h"
#include "store/forward.h"

class MemBuf;

namespace Store {

/// deserializes entry metadata size from the given buffer
/// \retval total swap metadata size (a.k.a. swap_hdr_len)
size_t UnpackSwapMetaSize(const SBuf &);

/// deserializes entry metadata from the given buffer into the cache index entry
/// \retval total swap metadata size (a.k.a. swap_hdr_len)
size_t UnpackIndexSwapMeta(const MemBuf &, StoreEntry &, cache_key *);

/// deserializes entry metadata from the given buffer into the cache hit entry
void UnpackHitSwapMeta(char const *, ssize_t, StoreEntry &);

} // namespace Store

#endif /* SQUID_SRC_STORE_SWAPMETAIN_H */

