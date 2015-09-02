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

#include <unordered_map>

namespace Auth {

class UserNameCache
{
private:
    /// key is Uer::userKey(), mapped value is User::Pointer
    typedef std::unordered_map<SBuf, Auth::User::Pointer> StoreType;

public:
    UserNameCache() = delete;
    explicit UserNameCache(const char *name);

    ~UserNameCache() = default;
    UserNameCache(const UserNameCache& ) = delete;
    UserNameCache& operator=(const UserNameCache&) = delete;

    /// obtain pointer to user if present, or Pointer(nullptr) if not
    Auth::User::Pointer lookup(const SBuf &userKey);

    /// add an user to the cache
    void insert(Auth::User::Pointer anAuth_user);

    void reset();

    size_t size();

    /** periodic cleanup function, removes timed-out entries
     *
     * Must be static to support EVH interface. Argument will be this
     */
    static void cleanup(void *);

    /** obtain sorted list of usernames
     *
     */
    std::vector<Auth::User::Pointer> sortedUsersList();
private:
    StoreType store_;

    // for logs, events etc.
    const char *cachename;
};

} /* namespace Auth */
#endif /* SQUID_USERNAMECACHE_H_ */
