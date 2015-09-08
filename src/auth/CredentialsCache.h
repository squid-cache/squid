/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_CREDENTIALSCACHE_H
#define SQUID_SRC_AUTH_CREDENTIALSCACHE_H

#include "auth/User.h"
#include "base/RunnersRegistry.h"
#include "cbdata.h"
#include "SBufAlgos.h"

#include <unordered_map>

namespace Auth {

/// Cache of Auth::User credentials, keyed by Auth::User::userKey
class CredentialsCache : public RegisteredRunner
{
private:
    CBDATA_CLASS(CredentialsCache);

    /// key is User::userKey(), mapped value is User::Pointer
    typedef std::unordered_map<SBuf, Auth::User::Pointer> StoreType;

public:
    CredentialsCache() = delete;
    explicit CredentialsCache(const char *name);

    ~CredentialsCache() = default;
    CredentialsCache(const CredentialsCache& ) = delete;
    CredentialsCache& operator=(const CredentialsCache&) = delete;

    /// obtain pointer to user if present, or Pointer(nullptr) if not
    /// \returns a pointer to cached credentials, or nil if none found
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

    /// cache garbage collection, removes timed-out entries
    void cleanup();

    /** obtain sorted list of usernames
     *
     */
    std::vector<Auth::User::Pointer> sortedUsersList() const;

    /* RegisteredRunner API */
    virtual void endingShutdown() override;
    virtual void syncConfig() override;

private:
    StoreType store_;

    // for logs, events etc.
    const char *cachename;

    // c_str() raw pointer is used in event. std::string must not reallocate
    // after ctor and until shutdown
    // must be unique
    std::string cacheCleanupEventName;
};

} /* namespace Auth */

#endif /* SQUID_SRC_AUTH_CREDENTIALSCACHE_H */

