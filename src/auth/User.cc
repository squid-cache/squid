/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 29    Authenticator */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/Gadgets.h"
#include "auth/Config.h"
#include "auth/CredentialsCache.h"
#include "auth/Gadgets.h"
#include "auth/User.h"
#include "auth/UserRequest.h"
#include "event.h"
#include "globals.h"
#include "Store.h"

Auth::User::User(Auth::SchemeConfig *aConfig, const char *aRequestRealm) :
    auth_type(Auth::AUTH_UNKNOWN),
    config(aConfig),
    expiretime(0),
    credentials_state(Auth::Unchecked),
    username_(nullptr),
    requestRealm_(aRequestRealm),
    ipList(256*1024) // XXX: figure a more reasonable value than ~256KB cache per-username
{
    proxy_match_cache.head = proxy_match_cache.tail = nullptr;
    debugs(29, 5, "Initialised auth_user '" << this << "'.");
}

Auth::CredentialState
Auth::User::credentials() const
{
    return credentials_state;
}

void
Auth::User::credentials(CredentialState newCreds)
{
    credentials_state = newCreds;
}

/**
 * Combine two user structs. ONLY to be called from within a scheme
 * module. The scheme module is responsible for ensuring that the
 * two users _can_ be merged without invalidating all the request
 * scheme data. The scheme is also responsible for merging any user
 * related scheme data itself.
 * The caller is responsible for altering all refcount pointers to
 * the 'from' object. They are invalid once this method is complete.
 */
void
Auth::User::absorb(Auth::User::Pointer from)
{
    /*
     * XXX Incomplete: it should merge in hash references too and ask the module to merge in scheme data
     *  dlink_list proxy_match_cache;
     */

    debugs(29, 5, "auth_user '" << from << "' into auth_user '" << this << "'.");

    // combine the helper response annotations. Ensuring no duplicates are copied.
    notes.appendNewOnly(&from->notes);

    /* absorb the list of IP address sources (for max_user_ip controls) */
    ipList.merge(from->ipList);

#if 0
    for (auto &newIp : from->ipList) {
        /* If this IP has expired - ignore the expensive merge actions. */
        if (!newIp.expired()) {
            /* add to our list. update if already present. */
            if (const auto *old = ipList.find(ipa.key))
                newIp.expires = max(newIp.expires, old->expires);
            ipList.add(newIp.key, newIp.value, newIp.expires);
        }
    }
#endif
}

Auth::User::~User()
{
    debugs(29, 5, "Freeing auth_user '" << this << "'.");
    assert(LockCount() == 0);

    /* free cached acl results */
    aclCacheMatchFlush(&proxy_match_cache);

    if (username_)
        xfree((char*)username_);

    /* prevent accidental reuse */
    auth_type = Auth::AUTH_UNKNOWN;
}

/// generate the cache key for an ipList entry
static const SBuf
BuildIpKey(const Ip::Address &ip)
{
    SBuf key;
    auto *buf = key.rawAppendStart(MAX_IPSTRLEN);
    const auto len = ip.toHostStr(buf, MAX_IPSTRLEN);
    key.rawAppendFinish(buf, len);
    return key;
}

void
Auth::User::clearIp()
{
    const auto savedLimit = ipList.memLimit();
    ipList.setMemLimit(0);
    ipList.setMemLimit(savedLimit);
}

void
Auth::User::removeIp(const Ip::Address &ip)
{
    ipList.del(BuildIpKey(ip));
}

void
Auth::User::addIp(const Ip::Address &ip)
{
    ipList.add(BuildIpKey(ip), ip, Auth::TheConfig.ipTtl);
    debugs(29, 2, "user '" << username() << "' has been seen at a new IP address (" << ip << ")");
}

SBuf
Auth::User::BuildUserKey(const char *username, const char *realm)
{
    SBuf key;
    if (realm)
        key.Printf("%s:%s", username, realm);
    else
        key.append(username, strlen(username));
    return key;
}

/**
 * Dump the username cache statistics for viewing...
 */
void
Auth::User::CredentialsCacheStats(StoreEntry *output)
{
    auto userlist = authenticateCachedUsersList();
    storeAppendPrintf(output, "Cached Usernames: %d", static_cast<int32_t>(userlist.size()));
    storeAppendPrintf(output, "\n%-15s %-9s %-9s %-9s %s\t%s\n",
                      "Type",
                      "State",
                      "Check TTL",
                      "Cache TTL",
                      "Username", "Key");
    storeAppendPrintf(output, "--------------- --------- --------- --------- ------------------------------\n");
    for ( auto auth_user : userlist ) {
        storeAppendPrintf(output, "%-15s %-9s %-9d %-9d %s\t" SQUIDSBUFPH "\n",
                          Auth::Type_str[auth_user->auth_type],
                          CredentialState_str[auth_user->credentials()],
                          auth_user->ttl(),
                          static_cast<int32_t>(auth_user->expiretime - squid_curtime + Auth::TheConfig.credentialsTtl),
                          auth_user->username(),
                          SQUIDSBUFPRINT(auth_user->userKey())
                         );
    }
}

void
Auth::User::username(char const *aString)
{
    if (aString) {
        assert(!username_);
        username_ = xstrdup(aString);
        // NP: param #2 is working around a c_str() data-copy performance regression
        userKey_ = BuildUserKey(username_, (!requestRealm_.isEmpty() ? requestRealm_.c_str() : nullptr));
    } else {
        safe_free(username_);
        userKey_.clear();
    }
}

