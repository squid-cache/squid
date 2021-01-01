/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef __AUTH_NTLM_H__
#define __AUTH_NTLM_H__

#if HAVE_AUTH_MODULE_NTLM

#include "auth/Config.h"
#include "auth/Gadgets.h"
#include "auth/UserRequest.h"
#include "helper/forward.h"

class HttpRequest;
class StoreEntry;

namespace Auth
{
namespace Ntlm
{

/** NTLM Authentication configuration data */
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
    virtual void registerWithCacheManager(void);
    virtual const char * type() const;

public:
    int keep_alive;
};

} // namespace Ntlm
} // namespace Auth

extern statefulhelper *ntlmauthenticators;

#endif /* HAVE_AUTH_MODULE_NTLM */
#endif

