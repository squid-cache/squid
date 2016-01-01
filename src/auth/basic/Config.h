/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef __AUTH_BASIC_H__
#define __AUTH_BASIC_H__

#if HAVE_AUTH_MODULE_BASIC

#include "auth/Config.h"
#include "auth/Gadgets.h"
#include "auth/UserRequest.h"
#include "helper/forward.h"

namespace Auth
{
namespace Basic
{

/** Basic authentication configuration data */
class Config : public Auth::Config
{
public:
    Config();
    virtual bool active() const;
    virtual bool configured() const;
    virtual Auth::UserRequest::Pointer decode(char const *proxy_auth, const char *requestRealm);
    virtual void done();
    virtual void rotateHelpers();
    virtual bool dump(StoreEntry *, const char *, Auth::Config *) const;
    virtual void fixHeader(Auth::UserRequest::Pointer, HttpReply *, Http::HdrType, HttpRequest *);
    virtual void init(Auth::Config *);
    virtual void parse(Auth::Config *, int, char *);
    void decode(char const *httpAuthHeader, Auth::UserRequest::Pointer);
    virtual void registerWithCacheManager(void);
    virtual const char * type() const;

public:
    time_t credentialsTTL;
    int casesensitive;
    int utf8;

private:
    char * decodeCleartext(const char *httpAuthHeader);
};

} // namespace Basic
} // namespace Auth

extern helper *basicauthenticators;

#endif /* HAVE_AUTH_MODULE_BASIC */
#endif /* __AUTH_BASIC_H__ */

