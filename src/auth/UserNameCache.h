/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_USERNAMECACHE_H_
#define SQUID_USERNAMECACHE_H_

#include "SBufAlgos.h"
#include "auth/User.h"
#include "cbdata.h"
#include "base/RunnersRegistry.h"

#include <unordered_map>

namespace Auth {

/** Cache of Auth::User::Pointer, keyed by Auth::User::userKey
 *
 * It's meant to be used as a per-authentication protocol cache,
 * cleaning up objects which are past authenticate_ttl life
 */
class UserNameCache : public RegisteredRunner
{
private:
    CBDATA_CLASS(UserNameCache);

    /// key is User::userKey(), mapped value is User::Pointer
    typedef std::unordered_map<SBuf, Auth::User::Pointer> StoreType;

public:
    UserNameCache() = delete;
    explicit UserNameCache(const char *name);

    ~UserNameCache() = default;
    UserNameCache(const UserNameCache& ) = delete;
    UserNameCache& operator=(const UserNameCache&) = delete;

    /// obtain pointer to user if present, or Pointer(nullptr) if not
    Auth::User::Pointer lookup(const SBuf &userKey) const;

    /// add an user to the cache
    void insert(Auth::User::Pointer anAuth_user);

    /// clear cache
    void reset() { store_.clear(); }

    /// extract number of cached usernames
    size_t size() const { return store_.size(); }

    /** periodic cleanup function, removes timed-out entries
     *
     * Must be static to support EVH interface. Argument will be this
     */
    static void Cleanup(void *);

    /** obtain sorted list of usernames
     *
     */
    std::vector<Auth::User::Pointer> sortedUsersList() const;

    /// RegisteredRunner API
    virtual void endingShutdown() override;

private:
    StoreType store_;

    // for logs, events etc.
    const char *cachename;

    // must be unique to the cache and valid for the object's lifetime
    std::string cacheCleanupEventName;
};

} /* namespace Auth */
#endif /* SQUID_USERNAMECACHE_H_ */
