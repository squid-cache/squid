/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_CREDENTIALSCACHE_H
#define SQUID_SRC_AUTH_CREDENTIALSCACHE_H

#include "auth/User.h"
#include "cbdata.h"
#include "sbuf/Algorithms.h"

#include <unordered_map>

namespace Auth {

/// Cache of Auth::User credentials, keyed by Auth::User::userKey
class CredentialsCache
{
    CBDATA_CLASS(CredentialsCache);

public:
    explicit CredentialsCache(const char *name, const char * const eventName);

    ~CredentialsCache() = default;
    CredentialsCache(const CredentialsCache&) = delete;
    CredentialsCache& operator=(const CredentialsCache&) = delete;

    /// \returns a pointer to cached credentials, or nil if none found
    Auth::User::Pointer lookup(const SBuf &userKey) const;

    /// add an user to the cache with the provided key
    void insert(const SBuf &userKey, Auth::User::Pointer anAuth_user);

    /// clear cache
    void reset() { store_.clear(); }

    /// \returns number of cached usernames
    size_t size() const { return store_.size(); }

    /** periodic cleanup function, removes timed-out entries
     *
     * Must be static to support EVH interface. Argument will be this
     */
    static void Cleanup(void *);

    /// cache garbage collection, removes timed-out entries
    void cleanup();

    /**
     * Cleanup cache data after a reconfiguration has occurred.
     * Similar to cleanup() but also flushes stale config dependent
     * state from retained entries.
     */
    void doConfigChangeCleanup();

    /// \returns alphanumerically sorted list of usernames
    std::vector<Auth::User::Pointer> sortedUsersList() const;

private:
    void scheduleCleanup();

    /// whether a cleanup (garbage collection) event has been scheduled
    bool gcScheduled_;

    /// key is User::userKey(), mapped value is User::Pointer
    typedef std::unordered_map<SBuf, Auth::User::Pointer> StoreType;
    StoreType store_;

    // c-string raw pointer used as event name
    const char * const cacheCleanupEventName;
};

} /* namespace Auth */

#endif /* SQUID_SRC_AUTH_CREDENTIALSCACHE_H */

