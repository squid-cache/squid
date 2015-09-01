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
#include "User.h"

#include <unordered_map>

namespace Auth {

class UserNameCache
{
private:
    /// key is Uer::userKey(), mapped value is User::Pointer
    typedef std::unordered_map<SBuf, User::Pointer> StoreType;

public:
    UserNameCache() = delete;
    explicit UserNameCache(const char *name) : cachename(name) {}

    ~UserNameCache() = default;
    UserNameCache(const UserNameCache& ) = delete;
    UserNameCache& operator=(const UserNameCache&) = delete;

    /// obtain pointer to user if present, or Pointer(nullptr) if not
    User::Pointer lookup(const SBuf &userKey);

    void reset();

    size_t size();

    /// periodic cleanup function, removes timed-out entries.
    void cleanup(void *);

private:
    StoreType store_;

    // for logs, events etc.
    const char *cachename;
};

} /* namespace Auth */
#endif /* SQUID_USERNAMECACHE_H_ */
