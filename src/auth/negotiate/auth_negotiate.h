/*
 * auth_negotiate.h
 * Internal declarations for the negotiate auth module
 */

#ifndef __AUTH_NEGOTIATE_H__
#define __AUTH_NEGOTIATE_H__

#include "auth/Config.h"
#include "auth/Gadgets.h"
#include "auth/UserRequest.h"
#include "helper.h"

/**
 \defgroup AuthNegotiateAPI Negotiate Authentication API
 \ingroup AuthAPI
 */

/// \ingroup AuthNegotiateAPI
#define DefaultAuthenticateChildrenMax  32	/* 32 processes */

namespace Auth
{
namespace Negotiate
{

/** Negotiate Authentication configuration data */
class Config : public Auth::Config
{
public:
    Config();
    virtual bool active() const;
    virtual bool configured() const;
    virtual Auth::UserRequest::Pointer decode(char const *proxy_auth);
    virtual void done();
    virtual void rotateHelpers();
    virtual void dump(StoreEntry *, const char *, Auth::Config *);
    virtual void fixHeader(Auth::UserRequest::Pointer, HttpReply *, http_hdr_type, HttpRequest *);
    virtual void init(Auth::Config *);
    virtual void parse(Auth::Config *, int, char *);
    virtual void registerWithCacheManager(void);
    virtual const char * type() const;

public:
    int keep_alive;
};

} // namespace Negotiate
} // namespace Auth

extern statefulhelper *negotiateauthenticators;

#endif
