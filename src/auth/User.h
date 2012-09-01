/*
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef SQUID_AUTH_USER_H
#define SQUID_AUTH_USER_H

#if USE_AUTH

#include "auth/CredentialState.h"
#include "auth/Type.h"
#include "dlink.h"
#include "ip/Address.h"
#include "RefCount.h"

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
    /** we may have many proxy-authenticate strings that decode to the same user */
    dlink_list proxy_auth_list;
    dlink_list proxy_match_cache;
    size_t ipcount;
    long expiretime;

public:
    static void cacheInit();
    static void CachedACLsReset();

    void absorb(Auth::User::Pointer from);
    virtual ~User();
    _SQUID_INLINE_ char const *username() const;
    _SQUID_INLINE_ void username(char const *);

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
    User(Auth::Config *);

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

    /** what ip addresses has this user been seen at?, plus a list length cache */
    dlink_list ip_list;
};

} // namespace Auth

#if _USE_INLINE_
#include "auth/User.cci"
#endif

#endif /* USE_AUTH */
#endif /* SQUID_AUTH_USER_H */
