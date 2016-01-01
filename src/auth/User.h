/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_AUTH_USER_H
#define SQUID_AUTH_USER_H

#if USE_AUTH

#include "auth/CredentialState.h"
#include "auth/Type.h"
#include "base/RefCount.h"
#include "dlink.h"
#include "ip/Address.h"
#include "Notes.h"
#include "SBuf.h"

class AuthUserHashPointer;
class StoreEntry;

namespace Auth
{

class Config;

/**
 *  \ingroup AuthAPI
 * This is the main user related structure. It stores user-related data,
 * and is persistent across requests. It can even persist across
 * multiple external authentications. One major benefit of preserving this
 * structure is the cached ACL match results. This structure, is private to
 * the authentication framework.
 */
class User : public RefCountable
{
public:
    typedef RefCount<User> Pointer;

    /* extra fields for proxy_auth */
    /* auth_type and auth_module are deprecated. Do Not add new users of these fields.
     * Aim to remove shortly
     */
    /** \deprecated this determines what scheme owns the user data. */
    Auth::Type auth_type;
    /** the config for this user */
    Auth::Config *config;
    dlink_list proxy_match_cache;
    size_t ipcount;
    long expiretime;

    /// list of key=value pairs the helper produced
    NotePairs notes;

public:
    static void cacheInit();
    static void CachedACLsReset();
    static SBuf BuildUserKey(const char *username, const char *realm);

    void absorb(Auth::User::Pointer from);
    virtual ~User();
    char const *username() const { return username_; }
    void username(char const *); ///< set stored username and userKey

    // NP: key is set at the same time as username_. Until then both are empty/NULL.
    const char *userKey() {return userKey_;}

    /**
     * How long these credentials are still valid for.
     * Negative numbers means already expired.
     */
    virtual int32_t ttl() const = 0;

    /* Manage list of IPs using this username */
    void clearIp();
    void removeIp(Ip::Address);
    void addIp(Ip::Address);

    void addToNameCache();
    static void UsernameCacheStats(StoreEntry * output);

    CredentialState credentials() const;
    void credentials(CredentialState);

private:
    /**
     * The current state these credentials are in:
     *   Unchecked
     *   Authenticated
     *   Pending helper result
     *   Handshake happening in stateful auth.
     *   Failed auth
     */
    CredentialState credentials_state;

protected:
    User(Auth::Config *, const char *requestRealm);

private:
    /**
     * Garbage Collection for the username cache.
     */
    static void cacheCleanup(void *unused);
    static time_t last_discard; /// Time of last username cache garbage collection.

    /**
     * DPW 2007-05-08
     * The username_ memory will be allocated via
     * xstrdup().  It is our responsibility.
     */
    const char *username_;

    /**
     * A realm for the user depending on request, designed to identify users,
     * with the same username and different authentication domains.
     * The requestRealm_ memory will be allocated via xstrdup().
     * It is our responsibility.
     */
    const char *requestRealm_;

    /**
     * A Unique key for the user, consist by username and realm.
     * The userKey_ memory will be allocated via xstrdup().
     * It is our responsibility.
     */
    const char *userKey_;

    /** what ip addresses has this user been seen at?, plus a list length cache */
    dlink_list ip_list;
};

} // namespace Auth

#endif /* USE_AUTH */
#endif /* SQUID_AUTH_USER_H */

