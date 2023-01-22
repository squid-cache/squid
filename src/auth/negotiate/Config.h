/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef __AUTH_NEGOTIATE_H__
#define __AUTH_NEGOTIATE_H__

#if HAVE_AUTH_MODULE_NEGOTIATE

#include "auth/Gadgets.h"
#include "auth/SchemeConfig.h"
#include "auth/UserRequest.h"
#include "helper/forward.h"

namespace Auth
{
namespace Negotiate
{

/** Negotiate Authentication configuration data */
class Config : public Auth::SchemeConfig
{
public:
    bool active() const override;
    bool configured() const override;
    Auth::UserRequest::Pointer decode(char const *proxy_auth, const HttpRequest *request, const char *requestRealm) override;
    void done() override;
    void rotateHelpers() override;
    void fixHeader(Auth::UserRequest::Pointer, HttpReply *, Http::HdrType, HttpRequest *) override;
    void init(Auth::SchemeConfig *) override;
    void registerWithCacheManager(void) override;
    const char * type() const override;
};

} // namespace Negotiate
} // namespace Auth

extern statefulhelper *negotiateauthenticators;

#endif /* HAVE_AUTH_MODULE_NEGOTIATE */
#endif

