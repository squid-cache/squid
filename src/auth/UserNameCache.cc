/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "event.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "auth/UserNameCache.h"

namespace Auth {

UserNameCache::UserNameCache(const char *name) :
    cachename(name), cacheCleanupEventName("User cache cleanup: ")
{
    cacheCleanupEventName.append(name);
    eventAdd(cacheCleanupEventName.c_str(), &UserNameCache::Cleanup,
                    this, ::Config.authenticateGCInterval, 1);
}

Auth::User::Pointer
UserNameCache::lookup(const SBuf &userKey)
{
    auto p = store_.find(userKey);
    if (p == store_.end())
        return User::Pointer(nullptr);
    return p->second;
}

void
UserNameCache::Cleanup(void *data)
{
    // data is this in disguise
    UserNameCache *self = static_cast<UserNameCache *>(data);
    // cache entries with expiretime <= expirationTime are to be evicted
    const time_t expirationTime =  current_time.tv_sec - ::Config.authenticateTTL;
    const auto end = self->store_.end();
    for (auto i = self->store_.begin(); i != end; ++i) {
        if (i->second->expiretime <= expirationTime)
            self->store_.erase(i);
    }
}

void
UserNameCache::insert(Auth::User::Pointer anAuth_user)
{
    store_[anAuth_user->SBUserKey()] = anAuth_user;
}

// generates the list of cached usernames in a format that is convenient
// to merge with equivalent lists obtained from other UserNameCaches.
std::vector<Auth::User::Pointer>
UserNameCache::sortedUsersList()
{
    std::vector<Auth::User::Pointer> rv(size(), nullptr);
    std::transform(store_.begin(), store_.end(), rv.begin(),
        [](StoreType::value_type v) { return v.second; }
    );
    sort(rv.begin(), rv.end(),
        [](const Auth::User::Pointer &lhs, const Auth::User::Pointer &rhs) {
            return strcmp(lhs->username(), rhs->username()) < 0;
        }
    );
    return rv;
}

} /* namespace Auth */
