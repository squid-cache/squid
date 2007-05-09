
/*
 * $Id: AuthUser.h,v 1.5 2007/05/09 08:26:57 wessels Exp $
 *
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

#ifndef SQUID_AUTHUSER_H
#define SQUID_AUTHUSER_H

class AuthUserRequest;

class AuthUser
{

public:
    /* extra fields for proxy_auth */
    /* auth_type and auth_module are deprecated. Do Not add new users of these fields.
     * Aim to remove shortly
     */
    /* this determines what scheme owns the user data. */
    auth_type_t auth_type;
    /* the config for this user */
    AuthConfig *config;
    /* we only have one username associated with a given auth_user struct */
    auth_user_hash_pointer *usernamehash;
    /* we may have many proxy-authenticate strings that decode to the same user */
    dlink_list proxy_auth_list;
    dlink_list proxy_match_cache;
    size_t ipcount;
    long expiretime;
    /* how many references are outstanding to this instance */
    size_t references;
    /* the auth_user_request structures that link to this. Yes it could be a splaytree
     * but how many requests will a single username have in parallel? */
    dlink_list requests;

    static void cacheInit ();
    static void CachedACLsReset();

    void absorb(auth_user_t *from);
    virtual ~AuthUser ();
    _SQUID_INLINE_ char const *username() const;
    _SQUID_INLINE_ void username(char const *);
    void clearIp();
    void removeIp(struct IN_ADDR);
    void addIp(struct IN_ADDR);
    _SQUID_INLINE_ void addRequest(AuthUserRequest *);

    void lock()

        ;
    void unlock();

    void addToNameCache();

protected:
    AuthUser (AuthConfig *);

private:
    static void cacheCleanup (void *unused);

    /*
     * DPW 2007-05-08
     * The username_ memory will be allocated via
     * xstrdup().  It is our responsibility.
     */
    char const *username_;

    /* what ip addresses has this user been seen at?, plus a list length cache */
    dlink_list ip_list;
};

#ifdef _USE_INLINE_
#include "AuthUser.cci"
#endif

#endif /* SQUID_AUTHUSER_H */
