/*
 * auth_ntlm.h
 * Internal declarations for the ntlm auth module
 */

#ifndef __AUTH_NTLM_H__
#define __AUTH_NTLM_H__
#include "authenticate.h"
#include "AuthUser.h"
#include "AuthUserRequest.h"
#include "AuthConfig.h"

#define DefaultAuthenticateChildrenMax  32	/* 32 processes */

typedef enum {
    AUTHENTICATE_STATE_NONE,
    AUTHENTICATE_STATE_NEGOTIATE,
    AUTHENTICATE_STATE_CHALLENGE,
    AUTHENTICATE_STATE_RESPONSE,
    AUTHENTICATE_STATE_DONE,
    AUTHENTICATE_STATE_FAILED
} auth_state_t;                 /* connection level auth state */

/* Generic */

typedef struct
{
    void *data;
    auth_user_request_t *auth_user_request;
    RH *handler;
}

authenticateStateData;

class NTLMUser : public AuthUser
{

public:
    MEMPROXY_CLASS(NTLMUser);
    virtual void deleteSelf() const;
    NTLMUser(AuthConfig *);
    ~NTLMUser();
    dlink_list proxy_auth_list;
};

MEMPROXY_CLASS_INLINE(NTLMUser)

typedef class NTLMUser ntlm_user_t;

class AuthNTLMUserRequest : public AuthUserRequest
{

public:
    MEMPROXY_CLASS(AuthNTLMUserRequest);

    AuthNTLMUserRequest();
    virtual ~AuthNTLMUserRequest();
    virtual int authenticated() const;
    virtual void authenticate(HttpRequest * request, ConnStateData::Pointer conn, http_hdr_type type);
    virtual int module_direction();
    virtual void onConnectionClose(ConnStateData *);
    virtual const char *connLastHeader();
    virtual void module_start(RH *, void *);
    virtual AuthUser *user() {return _theUser;}

    virtual const AuthUser *user() const {return _theUser;}

    virtual void user (AuthUser *aUser) {_theUser=dynamic_cast<NTLMUser *>(aUser);}

    /* what negotiate string did the client use? */
    char *ntlmnegotiate;
    /* what challenge did we give the client? */
    char *authchallenge;
    /* what authenticate string did we get? */
    char *ntlmauthenticate;
    /*we need to store the NTLM server between requests */
    helper_stateful_server *authserver;
    /* how far through the authentication process are we? */
    auth_state_t auth_state;
    /* have we got the helper-server in a deferred state? */
    int authserver_deferred;
    /* what connection is this associated with */
    ConnStateData::Pointer conn;

private:
    /* the user */
    NTLMUser * _theUser;
};

MEMPROXY_CLASS_INLINE(AuthNTLMUserRequest)

struct _ntlm_helper_state_t
{
    char *challenge;		/* the challenge to use with this helper */
    int starve;			/* 0= normal operation. 1=don't hand out any more challenges */
    int challengeuses;		/* the number of times this challenge has been issued */
    time_t renewed;
};

/* configuration runtime data */

class AuthNTLMConfig : public AuthConfig
{

public:
    AuthNTLMConfig::AuthNTLMConfig();
    virtual bool active() const;
    virtual bool configured() const;
    virtual AuthUserRequest *decode(char const *proxy_auth);
    virtual void done();
    virtual void dump(StoreEntry *, const char *, AuthConfig *);
    virtual void fixHeader(auth_user_request_t *, HttpReply *, http_hdr_type, HttpRequest *);
    virtual void init(AuthConfig *);
    virtual void parse(AuthConfig *, int, char *);
    virtual const char * type() const;
    int authenticateChildren;
    wordlist *authenticate;
    int challengeuses;
    time_t challengelifetime;
};

struct ProxyAuthCachePointer : public hash_link
{
    dlink_node link;
    /* other hash entries that point to the same auth_user */
    auth_user_t *auth_user;
};

typedef struct _ntlm_helper_state_t ntlm_helper_state_t;

typedef class AuthNTLMConfig auth_ntlm_config;

#endif
