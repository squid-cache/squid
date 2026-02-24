/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_AUTH_BEARER_FORWARD_H
#define _SQUID_SRC_AUTH_BEARER_FORWARD_H

#if HAVE_AUTH_MODULE_BEARER

#include "base/ClpMap.h"
#include "base/RefCount.h"
#include "sbuf/forward.h"

#include <map>

namespace Auth {

/** OAuth 2.0 Bearer token Authentication in HTTP
 *
 * RFC 6750 OAuth 2.0 Authorization Framework: Bearer Token Usage
 * http://tools.ietf.org/rfc/rfc6750
 */
namespace Bearer {

class Token;
class User;
class UserRequest;

using TokenPointer = RefCount<Token>;

uint64_t MemoryUsedByToken(const TokenPointer &);
using TokenCache = ClpMap<SBuf, TokenPointer, Bearer::MemoryUsedByToken>;

} // namespace Bearer
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_BEARER */
#endif /* _SQUID_SRC_AUTH_BEARER_FORWARD_H */
