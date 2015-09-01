/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "UserNameCache.h"

#include <algorithm>

namespace Auth {

User::Pointer
UserNameCache::lookup(const SBuf &userKey)
{
    auto p = store_.find(userKey);
    if (p == store_.end())
        return User::Pointer();
    return p->second;
}

void
UserNameCache::reset()
{
    store_.clear();
}

size_t
UserNameCache::size()
{
    return store_.size();
}

void
UserNameCache::cleanup(void *)
{
    // cache entries with expiretime <= expirationTime are to be evicted
    const time_t expirationTime =  current_time.tv_sec - ::Config.authenticateTTL;
    const auto end = store_.end();
    for (auto i = store_.begin(); i != end; ++i) {
        if (i->second->expiretime <= expirationTime)
            store_.erase(i);
    }
}

} /* namespace Auth */
