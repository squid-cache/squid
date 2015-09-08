/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 29    Authenticator */

#include "squid.h"
#include "acl/Gadgets.h"
#include "auth/CredentialsCache.h"
#include "Debug.h"
#include "event.h"
#include "SquidConfig.h"
#include "SquidTime.h"

namespace Auth {

CBDATA_CLASS_INIT(CredentialsCache);

CredentialsCache::CredentialsCache(const char *name) :
    cachename(name),
    cacheCleanupEventName("User cache cleanup: ")
{
    debugs(29, 5, "initializing " << name << " username cache");
    cacheCleanupEventName.append(name);
    eventAdd(cacheCleanupEventName.c_str(), &CredentialsCache::Cleanup,
             this, ::Config.authenticateGCInterval, 1);
    RegisterRunner(this);
}

Auth::User::Pointer
CredentialsCache::lookup(const SBuf &userKey) const
{
    debugs(29, 6, "lookup for " << userKey);
    auto p = store_.find(userKey);
    if (p == store_.end())
        return User::Pointer(nullptr);
    return p->second;
}

void
CredentialsCache::Cleanup(void *data)
{
    debugs(29, 5, "checkpoint");
    // data is this in disguise
    CredentialsCache *self = static_cast<CredentialsCache *>(data);
    self->cleanup();
}

void
CredentialsCache::cleanup()
{
    // cache entries with expiretime <= expirationTime are to be evicted
    const time_t expirationTime =  current_time.tv_sec - ::Config.authenticateTTL;

    const auto end = store_.end();
    for (auto i = store_.begin(); i != end;) {
        debugs(29, 6, "considering " << i->first << "(expires in " <<
               (expirationTime - i->second->expiretime) << " sec)");
        if (i->second->expiretime <= expirationTime) {
            debugs(29, 6, "evicting " << i->first);
            i = store_.erase(i); //erase advances i
        } else {
            ++i;
        }
    }
    eventAdd(cacheCleanupEventName.c_str(), &CredentialsCache::Cleanup,
             this, ::Config.authenticateGCInterval, 1);
}

void
CredentialsCache::insert(Auth::User::Pointer anAuth_user)
{
    debugs(29, 6, "adding " << anAuth_user->userKey());
    store_[anAuth_user->userKey()] = anAuth_user;
}

// generates the list of cached usernames in a format that is convenient
// to merge with equivalent lists obtained from other CredentialsCaches.
std::vector<Auth::User::Pointer>
CredentialsCache::sortedUsersList() const
{
    std::vector<Auth::User::Pointer> rv(size(), nullptr);
    std::transform(store_.begin(), store_.end(), rv.begin(),
    [](StoreType::value_type v) { return v.second; }
                  );
    std::sort(rv.begin(), rv.end(),
    [](const Auth::User::Pointer &lhs, const Auth::User::Pointer &rhs) {
        return strcmp(lhs->username(), rhs->username()) < 0;
    }
             );
    return rv;
}

void
CredentialsCache::endingShutdown()
{
    debugs(29, 5, "Shutting down username cache " << cachename);
    eventDelete(&CredentialsCache::Cleanup, this);
    reset();
}

void
CredentialsCache::syncConfig()
{
    debugs(29, 5, "Reconfiguring username cache " << cachename);
    for (auto i : store_) {
        aclCacheMatchFlush(&i.second->proxy_match_cache);
    }
}

} /* namespace Auth */

