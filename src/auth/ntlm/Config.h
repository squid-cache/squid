/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_NTLM_CONFIG_H
#define SQUID_SRC_AUTH_NTLM_CONFIG_H

#if HAVE_AUTH_MODULE_NTLM

#include "auth/Gadgets.h"
#include "auth/SchemeConfig.h"
#include "auth/UserRequest.h"
#include "helper/forward.h"

class HttpRequest;
class StoreEntry;

namespace Auth
{
namespace Ntlm
{

/** NTLM Authentication configuration data */
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

} // namespace Ntlm
} // namespace Auth

extern Helper::StatefulClientPointer ntlmauthenticators;

#endif /* HAVE_AUTH_MODULE_NTLM */
#endif /* SQUID_SRC_AUTH_NTLM_CONFIG_H */

