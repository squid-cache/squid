/*
 * auth_ntlm.h
 * Internal declarations for the ntlm auth module
 */

#ifndef __AUTH_NTLM_H__
#define __AUTH_NTLM_H__
#include "auth/Gadgets.h"
#include "auth/User.h"
#include "auth/UserRequest.h"
#include "auth/Config.h"
#include "helper.h"

#define DefaultAuthenticateChildrenMax  32	/* 32 processes */

class NTLMUser : public AuthUser
{

public:
    MEMPROXY_CLASS(NTLMUser);
    NTLMUser(AuthConfig *);
    ~NTLMUser();

    virtual int32_t ttl() const;

    dlink_list proxy_auth_list;
};

MEMPROXY_CLASS_INLINE(NTLMUser);

typedef class NTLMUser ntlm_user_t;

/* configuration runtime data */

class AuthNTLMConfig : public AuthConfig
{

public:
    AuthNTLMConfig();
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

typedef class AuthNTLMConfig auth_ntlm_config;

extern statefulhelper *ntlmauthenticators;

#endif
