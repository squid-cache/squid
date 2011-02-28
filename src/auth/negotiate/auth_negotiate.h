/*
 * auth_negotiate.h
 * Internal declarations for the negotiate auth module
 */

#ifndef __AUTH_NEGOTIATE_H__
#define __AUTH_NEGOTIATE_H__

#include "auth/Config.h"
#include "auth/Gadgets.h"
#include "auth/State.h"
#include "auth/User.h"
#include "auth/UserRequest.h"
#include "helper.h"

/**
 \defgroup AuthNegotiateAPI Negotiate Authentication API
 \ingroup AuthAPI
 */

/// \ingroup AuthNegotiateAPI
#define DefaultAuthenticateChildrenMax  32	/* 32 processes */

/// \ingroup AuthNegotiateAPI
class NegotiateUser : public AuthUser
{

public:
    MEMPROXY_CLASS(NegotiateUser);
    NegotiateUser(AuthConfig *);
    ~NegotiateUser();
    virtual int32_t ttl() const;

    dlink_list proxy_auth_list;
};

MEMPROXY_CLASS_INLINE(NegotiateUser);

extern statefulhelper *negotiateauthenticators;

/* configuration runtime data */

/// \ingroup AuthNegotiateAPI
class AuthNegotiateConfig : public AuthConfig
{

public:
    AuthNegotiateConfig();
    virtual bool active() const;
    virtual bool configured() const;
    virtual AuthUserRequest::Pointer decode(char const *proxy_auth);
    virtual void done();
    virtual void rotateHelpers();
    virtual void dump(StoreEntry *, const char *, AuthConfig *);
    virtual void fixHeader(AuthUserRequest::Pointer, HttpReply *, http_hdr_type, HttpRequest *);
    virtual void init(AuthConfig *);
    virtual void parse(AuthConfig *, int, char *);
    virtual void registerWithCacheManager(void);
    virtual const char * type() const;
    int keep_alive;
};

extern AuthNegotiateConfig negotiateConfig;

#endif
