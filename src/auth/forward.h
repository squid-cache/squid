/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_FORWARD_H
#define SQUID_SRC_AUTH_FORWARD_H

#if USE_AUTH

#include <vector>

/// HTTP Authentication
namespace Auth
{

class CredentialsCache;

class Scheme;
class SchemeConfig;
typedef std::vector<Auth::SchemeConfig *> ConfigVector;

} // namespace Auth

#endif /* USE_AUTH */
#endif /* SQUID_SRC_AUTH_FORWARD_H */

