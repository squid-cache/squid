/*
 * auth_basic.h
 * Internal declarations for the basic auth module
 */

#ifndef __AUTH_BASIC_H__
#define __AUTH_BASIC_H__
#include "authenticate.h"
#include "AuthUser.h"
#include "AuthUserRequest.h"
#include "AuthConfig.h"
#include "helper.h"

#define DefaultAuthenticateChildrenMax  32	/* 32 processes */

/* Generic */

class AuthenticateStateData
{

public:
    void *data;
    AuthUserRequest *auth_user_request;
    RH *handler;
};

/* queue of auth requests waiting for verification to occur */

class BasicAuthQueueNode
{

public:
    BasicAuthQueueNode *next;
    AuthUserRequest *auth_user_request;
    RH *handler;
    void *data;
};

class AuthBasicUserRequest;

class BasicUser : public AuthUser
{

public:
    MEMPROXY_CLASS(BasicUser);

    virtual void deleteSelf() const;
    BasicUser(AuthConfig *);
    ~BasicUser();
    bool authenticated() const;
    void queueRequest(AuthUserRequest * auth_user_request, RH * handler, void *data);
    void submitRequest (AuthUserRequest * auth_user_request, RH * handler, void *data);
    void decode(char const *credentials, AuthUserRequest *);
    char *getCleartext() {return cleartext;}

    bool valid() const;
    void makeLoggingInstance(AuthBasicUserRequest *auth_user_request);
    AuthUser * makeCachedFrom();
    void updateCached(BasicUser *from);
    char *passwd;
    time_t credentials_checkedtime;

    struct
    {

unsigned int credentials_ok:
        2;	/*0=unchecked,1=ok,2=failed */
    }

    flags;
    BasicAuthQueueNode *auth_queue;

private:
    bool decodeCleartext();
    void extractUsername();
    void extractPassword();
    char *cleartext;
    AuthUserRequest *currentRequest;
    char const *httpAuthHeader;
};

MEMPROXY_CLASS_INLINE(BasicUser)

typedef class BasicUser basic_data;

/* follows the http request around */

class AuthBasicUserRequest : public AuthUserRequest
{

public:
    MEMPROXY_CLASS(AuthBasicUserRequest);

    AuthBasicUserRequest();
    virtual ~AuthBasicUserRequest();

    virtual int authenticated() const;
    virtual void authenticate(HttpRequest * request, ConnStateData::Pointer conn, http_hdr_type type);
    virtual int module_direction();
    virtual void module_start(RH *, void *);
    virtual AuthUser *user() {return _theUser;}

    virtual const AuthUser *user() const {return _theUser;}

    virtual void user (AuthUser *aUser) {_theUser=dynamic_cast<BasicUser *>(aUser);}

private:
    BasicUser *_theUser;
};

MEMPROXY_CLASS_INLINE(AuthBasicUserRequest)

/* configuration runtime data */

class AuthBasicConfig : public AuthConfig
{

public:
    AuthBasicConfig();
    ~AuthBasicConfig();
    virtual bool active() const;
    virtual bool configured() const;
    virtual AuthUserRequest *decode(char const *proxy_auth);
    virtual void done();
    virtual void dump(StoreEntry *, const char *, AuthConfig *);
    virtual void fixHeader(AuthUserRequest *, HttpReply *, http_hdr_type, HttpRequest *);
    virtual void init(AuthConfig *);
    virtual void parse(AuthConfig *, int, char *);
    virtual void registerWithCacheManager(CacheManager & manager);
    virtual const char * type() const;
    int authenticateChildren;
    int authenticateConcurrency;
    char *basicAuthRealm;
    wordlist *authenticate;
    time_t credentialsTTL;
    int casesensitive;
};

#endif
