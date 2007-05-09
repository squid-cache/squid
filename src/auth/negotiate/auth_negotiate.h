/*
 * auth_negotiate.h
 * Internal declarations for the negotiate auth module
 */

#ifndef __AUTH_NEGOTIATE_H__
#define __AUTH_NEGOTIATE_H__
#include "authenticate.h"
#include "AuthUser.h"
#include "AuthUserRequest.h"
#include "AuthConfig.h"
#include "helper.h"

#define DefaultAuthenticateChildrenMax  32	/* 32 processes */

#ifndef __AUTH_AUTHENTICATE_STATE_T__
#define __AUTH_AUTHENTICATE_STATE_T__
typedef enum {
    AUTHENTICATE_STATE_NONE,
    AUTHENTICATE_STATE_INITIAL,
    AUTHENTICATE_STATE_IN_PROGRESS,
    AUTHENTICATE_STATE_DONE,
    AUTHENTICATE_STATE_FAILED
} auth_state_t;                 /* connection level auth state */

/* Generic */

typedef struct
{
    void *data;
    AuthUserRequest *auth_user_request;
    RH *handler;
}

authenticateStateData;
#endif

class NegotiateUser : public AuthUser
{

public:
    MEMPROXY_CLASS(NegotiateUser);
    virtual void deleteSelf() const;
    NegotiateUser(AuthConfig *);
    ~NegotiateUser();
    dlink_list proxy_auth_list;
};

MEMPROXY_CLASS_INLINE(NegotiateUser)

typedef class NegotiateUser negotiate_user_t;

class AuthNegotiateUserRequest : public AuthUserRequest
{

public:
    MEMPROXY_CLASS(AuthNegotiateUserRequest);

    AuthNegotiateUserRequest();
    virtual ~AuthNegotiateUserRequest();
    virtual int authenticated() const;
    virtual void authenticate(HttpRequest * request, ConnStateData::Pointer conn, http_hdr_type type);
    virtual int module_direction();
    virtual void onConnectionClose(ConnStateData *);
    virtual void module_start(RH *, void *);
    virtual AuthUser *user() {return _theUser;}

    virtual const AuthUser *user() const {return _theUser;}

    virtual void addHeader(HttpReply * rep, int accel);

    virtual void user (AuthUser *aUser) {_theUser=dynamic_cast<NegotiateUser *>(aUser);}

    virtual const char * connLastHeader();

    /*we need to store the helper server between requests */
    helper_stateful_server *authserver;
    /* what connection is this associated with */
    ConnStateData::Pointer conn;

    /* how far through the authentication process are we? */
    auth_state_t auth_state;

    /* our current blob to pass to the client */
    char *server_blob;
    /* our current blob to pass to the server */
    char *client_blob;

    /* currently waiting for helper response */
    unsigned char waiting;

private:
    /* the user */
    NegotiateUser * _theUser;
};

MEMPROXY_CLASS_INLINE(AuthNegotiateUserRequest)

/* configuration runtime data */

class AuthNegotiateConfig : public AuthConfig
{

public:
    AuthNegotiateConfig();
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
    int keep_alive;
    wordlist *authenticate;
};

typedef class AuthNegotiateConfig auth_negotiate_config;

#endif
