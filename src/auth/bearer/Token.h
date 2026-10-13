/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_AUTH_BEARER_TOKEN_H
#define _SQUID_SRC_AUTH_BEARER_TOKEN_H

#if HAVE_AUTH_MODULE_BEARER

#include "auth/bearer/forward.h"
#include "base/RefCount.h"
#include "sbuf/SBuf.h"
#include "time/gadgets.h"

namespace Auth {
namespace Bearer {

/// a Bearer token we have seen and details we associate with it
class Token : public RefCountable
{
    MEMPROXY_CLASS(Auth::Bearer::Token);

public:
    Token() : expires(squid_curtime) {}
    explicit Token(const SBuf &token) : b68encoded(token), expires(squid_curtime) {}
    virtual ~Token() {}
    Token(const Token &) = delete;
    Token &operator =(const Token&) = delete;

    /// the B68 encoding form of this token
    SBuf b68encoded;

    /// the Auth::User this token is tied to
    Auth::Bearer::User *user = nullptr;

    /// this token should be ignored when received passed this time
    time_t expires = 0;

    /// a cache of known tokens
    static TokenCache Cache;
};

} // namespace Bearer
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_BEARER */
#endif /* _SQUID_SRC_AUTH_BEARER_TOKEN_H */
