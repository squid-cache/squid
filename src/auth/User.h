/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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
#include "base/CbcPointer.h"
#include "base/RefCount.h"
#include "dlink.h"
#include "ip/Address.h"
#include "Notes.h"
#include "sbuf/SBuf.h"

class StoreEntry;

namespace Auth
{

class Config;
class CredentialsCache;

/**
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

protected:
    User(Auth::Config *, const char *requestRealm);
public:
    virtual ~User();

    /* extra fields for proxy_auth */
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
    static SBuf BuildUserKey(const char *username, const char *realm);

    void absorb(Auth::User::Pointer from);
    char const *username() const { return username_; }
    void username(char const *); ///< set stored username and userKey

    // NP: key is set at the same time as username_. Until then both are empty/NULL.
    const SBuf userKey() const {return userKey_;}

    /**
     * How long these credentials are still valid for.
     * Negative numbers means already expired.
     */
    virtual int32_t ttl() const = 0;

    /* Manage list of IPs using this username */
    void clearIp();
    void removeIp(Ip::Address);
    void addIp(Ip::Address);

    /// add the Auth::User to the protocol-specific username cache.
    virtual void addToNameCache() = 0;
    static void CredentialsCacheStats(StoreEntry * output);

    // userKey ->Auth::User::Pointer cache
    // must be reimplemented in subclasses
    static CbcPointer<Auth::CredentialsCache> Cache();

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

private:
    /**
     * DPW 2007-05-08
     * The username_ memory will be allocated via
     * xstrdup().  It is our responsibility.
     */
    const char *username_;

    /**
     * A realm for the user depending on request, designed to identify users,
     * with the same username and different authentication domains.
     */
    SBuf requestRealm_;

    /**
     * A Unique key for the user, consist by username and requestRealm_
     */
    SBuf userKey_;

    /** what ip addresses has this user been seen at?, plus a list length cache */
    dlink_list ip_list;
};

} // namespace Auth

#endif /* USE_AUTH */
#endif /* SQUID_AUTH_USER_H */

