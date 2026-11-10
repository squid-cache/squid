/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_DIGEST_FORWARD_H
#define SQUID_SRC_AUTH_DIGEST_FORWARD_H

#if HAVE_AUTH_MODULE_DIGEST

namespace Auth
{

/// HTTP Digest Authentication
namespace Digest
{

class Config;
class Nonce;
class User;
class UserRequest;

} // namespace Digest
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_DIGEST */
#endif /* SQUID_SRC_AUTH_DIGEST_FORWARD_H */
