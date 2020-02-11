/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 29    Authenticator */

#include "squid.h"
#include "acl/Gadgets.h"
#include "auth/CredentialsCache.h"
#include "base/RunnersRegistry.h"
#include "Debug.h"
#include "event.h"
#include "SquidConfig.h"
#include "SquidTime.h"

namespace Auth {

class CredentialCacheRr : public RegisteredRunner
{
public:
    explicit CredentialCacheRr(const char *n, CredentialsCache * const c) :
        name(n),
        whichCache(c)
    {}

    virtual ~CredentialCacheRr() {
        debugs(29, 5, "Terminating Auth credentials cache: " << name);
        // invalidate the CBDATA reference.
        // causes Auth::*::User::Cache() to produce nil / invalid pointer
        delete whichCache.get();
    }

    virtual void endingShutdown() override {
        debugs(29, 5, "Clearing Auth credentials cache: " << name);
        whichCache->reset();
    }

    virtual void syncConfig() override {
        debugs(29, 5, "Reconfiguring Auth credentials cache: " << name);
        whichCache->doConfigChangeCleanup();
    }

private:
    /// name of the cache being managed, for logs
    const char *name;

    /// reference to the scheme cache which is being managed
    CbcPointer<CredentialsCache> whichCache;
};

CBDATA_CLASS_INIT(CredentialsCache);

CredentialsCache::CredentialsCache(const char *name, const char * const prettyEvName) :
    gcScheduled_(false),
    cacheCleanupEventName(prettyEvName)
{
    debugs(29, 5, "initializing " << name << " credentials cache");
    RegisterRunner(new Auth::CredentialCacheRr(name, this));
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
    gcScheduled_ = false;
    scheduleCleanup();
}

void
CredentialsCache::insert(const SBuf &userKey, Auth::User::Pointer anAuth_user)
{
    debugs(29, 6, "adding " << userKey << " (" << anAuth_user->username() << ")");
    store_[userKey] = anAuth_user;
    scheduleCleanup();
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
CredentialsCache::scheduleCleanup()
{
    if (!gcScheduled_ && store_.size()) {
        gcScheduled_ = true;
        eventAdd(cacheCleanupEventName, &CredentialsCache::Cleanup,
                 this, ::Config.authenticateGCInterval, 1);
    }
}

void
CredentialsCache::doConfigChangeCleanup()
{
    // purge expired entries entirely
    cleanup();
    // purge the ACL match data stored in the credentials
    for (auto i : store_) {
        aclCacheMatchFlush(&i.second->proxy_match_cache);
    }
}

} /* namespace Auth */

