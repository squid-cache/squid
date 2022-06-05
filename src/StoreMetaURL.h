/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREMETAURL_H
#define SQUID_STOREMETAURL_H

#include "store/forward.h"

namespace Store {

void CheckSwapMetaUrl(const SwapMetaView &, const StoreEntry &);

}

#endif /* SQUID_STOREMETAURL_H */

