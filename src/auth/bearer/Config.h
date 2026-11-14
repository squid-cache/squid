/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_AUTH_BEARER_CONFIG_H
#define _SQUID_SRC_AUTH_BEARER_CONFIG_H

#if HAVE_AUTH_MODULE_BEARER

#include "auth/bearer/forward.h"
#include "auth/Config.h"
#include "auth/Gadgets.h"
#include "auth/UserRequest.h"
#include "helper/forward.h"

namespace Auth
{
namespace Bearer
{

/// Bearer authentication configuration data
class Config : public SchemeConfig
{
public:
    Config();
    virtual ~Config();

    /* Auth::SchemeConfig API */
    bool active() const override;
    Auth::UserRequest::Pointer decode(char const *, const HttpRequest *, const char *) override;
    void done() override;
    bool configured() const override;
    void rotateHelpers(void) override;
    bool dump(StoreEntry *, const char *, SchemeConfig *) const override;
    void fixHeader(Auth::UserRequest::Pointer, HttpReply *, Http::HdrType, HttpRequest *) override;
    void init(SchemeConfig *) override;
    void registerWithCacheManager(void) override;
    void parse(SchemeConfig *, int, char *) override;
    const char * type() const override;

public:
    const char *bearerAuthScope = nullptr;

private:
    void tokenCacheSetup();
};

} // namespace Bearer
} // namespace Auth

extern Helper::ClientPointer bearerauthenticators;

#endif /* HAVE_AUTH_MODULE_BEARER */
#endif /* _SQUID_SRC_AUTH_BEARER_CONFIG_H */
