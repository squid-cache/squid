/*
 * $Id$
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
 */

#ifndef SQUID_AUTH_GADGETS_H
#define SQUID_AUTH_GADGETS_H

#include "hash.h"
#include "MemPool.h"
#include "typedefs.h" /* for authConfig */

class AuthUser;

/**
 \ingroup AuthAPI
 *
 * This is used to link auth_users into the username cache.
 * Because some schemes may link in aliases to a user,
 * the link is not part of the AuthUser structure itself.
 *
 \todo Inheritance in a struct? this should be a class.
 */
struct AuthUserHashPointer : public hash_link {
    /* first two items must be same as hash_link */

public:
    static void removeFromCache (void *anAuthUserHashPointer);
    MEMPROXY_CLASS(AuthUserHashPointer);

    AuthUserHashPointer(AuthUser *);

    AuthUser *user() const;

private:
    AuthUser *auth_user;
};

MEMPROXY_CLASS_INLINE(AuthUserHashPointer);

class ConnStateData;
class AuthScheme;
class StoreEntry;

/**
 \ingroup AuthAPI
 \todo this should be a generic cachemgr API type ?
 */
typedef void AUTHSSTATS(StoreEntry *);

/**
 \ingroup AuthAPI
 * subsumed by the C++ interface
 \todo does 'subsumed' mean deprecated use a C++ API call?
 */
extern void authenticateAuthUserMerge(AuthUser *, AuthUser *);

/// \ingroup AuthAPI
extern void authenticateInit(authConfig *);
/// \ingroup AuthAPI
extern void authenticateShutdown(void);
/// \ingroup AuthAPI
extern int authenticateAuthUserInuse(AuthUser * auth_user);

/// \ingroup AuthAPI
extern void authenticateFreeProxyAuthUserACLResults(void *data);
/// \ingroup AuthAPI
extern int authenticateActiveSchemeCount(void);
/// \ingroup AuthAPI
extern int authenticateSchemeCount(void);

/// \ingroup AuthAPI
extern void authenticateUserCacheRestart(void);
/// \ingroup AuthAPI
extern void authenticateOnCloseConnection(ConnStateData * conn);

#endif /* SQUID_AUTH_GADGETS_H */
