/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_BASIC_CONFIG_H
#define SQUID_SRC_AUTH_BASIC_CONFIG_H

#if HAVE_AUTH_MODULE_BASIC

#include "auth/Gadgets.h"
#include "auth/SchemeConfig.h"
#include "auth/UserRequest.h"
#include "helper/forward.h"

namespace Auth
{
namespace Basic
{

/** Basic authentication configuration data */
class Config : public Auth::SchemeConfig
{
public:
    Config();
    bool active() const override;
    bool configured() const override;
    Auth::UserRequest::Pointer decode(char const *proxy_auth, const HttpRequest *request, const char *requestRealm) override;
    void done() override;
    void rotateHelpers() override;
    bool dump(StoreEntry *, const char *, Auth::SchemeConfig *) const override;
    void fixHeader(Auth::UserRequest::Pointer, HttpReply *, Http::HdrType, HttpRequest *) override;
    void init(Auth::SchemeConfig *) override;
    void parse(Auth::SchemeConfig *, int, char *) override;
    void decode(char const *httpAuthHeader, Auth::UserRequest::Pointer);
    void registerWithCacheManager(void) override;
    const char * type() const override;

public:
    time_t credentialsTTL;
    int casesensitive;

private:
    char * decodeCleartext(const char *httpAuthHeader, const HttpRequest *request);
};

} // namespace Basic
} // namespace Auth

extern helper *basicauthenticators;

#endif /* HAVE_AUTH_MODULE_BASIC */
#endif /* SQUID_SRC_AUTH_BASIC_CONFIG_H */

