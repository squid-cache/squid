/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREMETAMD5_H
#define SQUID_STOREMETAMD5_H

#include "md5.h"
#include "store/forward.h"
#include "StoreMeta.h"

namespace Store {

void CheckSwapMetaMd5(const SwapMetaView &, const StoreEntry &);
void GetSwapMetaMd5(const SwapMetaView &, cache_key *);

}

#endif /* SQUID_STOREMETAMD5_H */

