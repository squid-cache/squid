/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREMETAVARY_H
#define SQUID_STOREMETAVARY_H

#include "sbuf/forward.h"
#include "store/forward.h"

namespace Store {

/// Stored Vary header field(s) that are not known to the entry (or empty SBuf)
SBuf GetNewSwapMetaVaryHeaders(const SwapMetaView &, const StoreEntry &);

}

#endif /* SQUID_STOREMETAVARY_H */

