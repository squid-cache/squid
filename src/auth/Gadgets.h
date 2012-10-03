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
 */

#ifndef SQUID_AUTH_GADGETS_H
#define SQUID_AUTH_GADGETS_H

#if USE_AUTH

#include "hash.h"
#include "MemPool.h"
#include "auth/Config.h"
#include "auth/User.h"

/**
 \ingroup AuthAPI
 *
 * This is used to link AuthUsers objects into the username cache.
 * Because some schemes may link in aliases to a user,
 * the link is not part of the AuthUser structure itself.
 *
 * Code must not hold onto copies of these objects.
 * They may exist only so long as the AuthUser being referenced
 * is recorded in the cache. Any caller using hash_remove_link
 * must then delete the AuthUserHashPointer.
 */
class AuthUserHashPointer : public hash_link
{
    /* first two items must be same as hash_link */

public:
    MEMPROXY_CLASS(AuthUserHashPointer);

    AuthUserHashPointer(Auth::User::Pointer);
    ~AuthUserHashPointer() { auth_user = NULL; };

    Auth::User::Pointer user() const;

private:
    Auth::User::Pointer auth_user;
};

MEMPROXY_CLASS_INLINE(AuthUserHashPointer);

namespace Auth
{
class Scheme;
}
class ConnStateData;
class StoreEntry;

/**
 \ingroup AuthAPI
 \todo this should be a generic cachemgr API type ?
 */
typedef void AUTHSSTATS(StoreEntry *);

/// \ingroup AuthAPI
void authenticateInit(Auth::ConfigVector *);

/** \ingroup AuthAPI
 * Remove all idle authentication state. Intended for use by reconfigure.
 *
 * Removes the username cache contents and global configuration state.
 * Stops just short of detaching the auth components completely.
 *
 * Currently active requests should finish. Howevee new requests will not use
 * authentication unless something causes the global config to be rebuilt.
 * Such as a configure load action adding config and re-running authenticateInit().
 */
void authenticateReset(void);

void authenticateRotate(void);

/// \ingroup AuthAPI
void authenticateFreeProxyAuthUserACLResults(void *data);
/// \ingroup AuthAPI
int authenticateActiveSchemeCount(void);
/// \ingroup AuthAPI
int authenticateSchemeCount(void);

/// \ingroup AuthAPI
void authenticateOnCloseConnection(ConnStateData * conn);

#endif /* USE_AUTH */
#endif /* SQUID_AUTH_GADGETS_H */
