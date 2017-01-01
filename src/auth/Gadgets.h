/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_AUTH_GADGETS_H
#define SQUID_AUTH_GADGETS_H

#if USE_AUTH

#include "auth/Config.h"
#include "auth/User.h"
#include "hash.h"
#include "MemPool.h"

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

