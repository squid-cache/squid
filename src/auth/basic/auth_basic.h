/*
 * auth_basic.h
 * Internal declarations for the basic auth module
 */

#ifndef __AUTH_BASIC_H__
#define __AUTH_BASIC_H__

#include "auth/Gadgets.h"
#include "auth/User.h"
#include "auth/UserRequest.h"
#include "auth/Config.h"
#include "helper.h"

#define DefaultAuthenticateChildrenMax  32	/* 32 processes */

/** queue of auth requests waiting for verification to occur */
class BasicAuthQueueNode
{

public:
    BasicAuthQueueNode *next;
    AuthUserRequest::Pointer auth_user_request;
    RH *handler;
    void *data;
};

class BasicUser : public AuthUser
{

public:
    MEMPROXY_CLASS(BasicUser);

    virtual void deleteSelf() const;
    BasicUser(AuthConfig *);
    ~BasicUser();
    bool authenticated() const;
    void queueRequest(AuthUserRequest::Pointer auth_user_request, RH * handler, void *data);
    void submitRequest(AuthUserRequest::Pointer auth_user_request, RH * handler, void *data);
    void decode(char const *credentials, AuthUserRequest::Pointer);
    char *getCleartext() {return cleartext;}

    bool valid() const;
    void makeLoggingInstance(AuthUserRequest::Pointer auth_user_request);
    AuthUser * makeCachedFrom();
    void updateCached(BasicUser *from);
    char *passwd;
    time_t credentials_checkedtime;

    struct {

unsigned int credentials_ok:
        2;	/*0=unchecked,1=ok,2=failed */
    } flags;
    BasicAuthQueueNode *auth_queue;

private:
    bool decodeCleartext();
    void extractUsername();
    void extractPassword();
    char *cleartext;
    AuthUserRequest::Pointer currentRequest;
    char const *httpAuthHeader;
};

MEMPROXY_CLASS_INLINE(BasicUser);

typedef class BasicUser basic_data;

#include "HelperChildConfig.h"

/* configuration runtime data */

class AuthBasicConfig : public AuthConfig
{

public:
    AuthBasicConfig();
    ~AuthBasicConfig();
    virtual bool active() const;
    virtual bool configured() const;
    virtual AuthUserRequest::Pointer decode(char const *proxy_auth);
    virtual void done();
    virtual void dump(StoreEntry *, const char *, AuthConfig *);
    virtual void fixHeader(AuthUserRequest::Pointer, HttpReply *, http_hdr_type, HttpRequest *);
    virtual void init(AuthConfig *);
    virtual void parse(AuthConfig *, int, char *);
    virtual void registerWithCacheManager(void);
    virtual const char * type() const;
    HelperChildConfig authenticateChildren;
    char *basicAuthRealm;
    wordlist *authenticate;
    time_t credentialsTTL;
    int casesensitive;
    int utf8;
};

#endif
