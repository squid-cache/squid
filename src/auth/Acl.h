/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_AUTH_ACL_H
#define SQUID_AUTH_ACL_H

#if USE_AUTH

#include "acl/Acl.h"

// ACL-related code used by authentication-related code. This code is not in
// auth/Gadgets to avoid making auth/libauth dependent on acl/libstate because
// acl/libstate already depends on auth/libauth.

class ACLChecklist;
/// \ingroup AuthAPI
allow_t AuthenticateAcl(ACLChecklist *ch);

#endif /* USE_AUTH */
#endif /* SQUID_AUTH_ACL_H */

