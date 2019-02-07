/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
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

std::vector<Auth::User::Pointer> authenticateCachedUsersList();

#endif /* USE_AUTH */
#endif /* SQUID_AUTH_GADGETS_H */

