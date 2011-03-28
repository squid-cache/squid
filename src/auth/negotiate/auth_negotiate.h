/*
 * auth_negotiate.h
 * Internal declarations for the negotiate auth module
 */

#ifndef __AUTH_NEGOTIATE_H__
#define __AUTH_NEGOTIATE_H__
#include "auth/Gadgets.h"
#include "auth/User.h"
#include "auth/UserRequest.h"
#include "auth/Config.h"
#include "helper.h"

/**
 \defgroup AuthNegotiateAPI Negotiate Authentication API
 \ingroup AuthAPI
 */

/// \ingroup AuthNegotiateAPI
#define DefaultAuthenticateChildrenMax  32	/* 32 processes */

#ifndef __AUTH_AUTHENTICATE_STATE_T__
#define __AUTH_AUTHENTICATE_STATE_T__

/// \ingroup AuthNegotiateAPI
typedef enum {
    AUTHENTICATE_STATE_NONE,
    AUTHENTICATE_STATE_INITIAL,
    AUTHENTICATE_STATE_IN_PROGRESS,
    AUTHENTICATE_STATE_DONE,
    AUTHENTICATE_STATE_FAILED
} auth_state_t;                 /* connection level auth state */

/* Generic */

/// \ingroup AuthNegotiateAPI
typedef struct {
    void *data;
    AuthUserRequest *auth_user_request;
    RH *handler;
} authenticateStateData;
#endif

/// \ingroup AuthNegotiateAPI
class NegotiateUser : public AuthUser
{

public:
    MEMPROXY_CLASS(NegotiateUser);
    virtual void deleteSelf() const;
    NegotiateUser(AuthConfig *);
    ~NegotiateUser();
    dlink_list proxy_auth_list;
};

MEMPROXY_CLASS_INLINE(NegotiateUser);

/// \ingroup AuthNegotiateAPI
typedef class NegotiateUser negotiate_user_t;

/// \ingroup AuthNegotiateAPI
class AuthNegotiateUserRequest : public AuthUserRequest
{

public:
    MEMPROXY_CLASS(AuthNegotiateUserRequest);

    AuthNegotiateUserRequest();
    virtual ~AuthNegotiateUserRequest();
    virtual int authenticated() const;
    virtual void authenticate(HttpRequest * request, ConnStateData * conn, http_hdr_type type);
    virtual int module_direction();
    virtual void onConnectionClose(ConnStateData *);
    virtual void module_start(RH *, void *);

    virtual void addHeader(HttpReply * rep, int accel);

    virtual const char * connLastHeader();

    /*we need to store the helper server between requests */
    helper_stateful_server *authserver;
    void releaseAuthServer(void); ///< Release the authserver helper server properly.

    /* what connection is this associated with */
    /* ConnStateData * conn;*/

    /* how far through the authentication process are we? */
    auth_state_t auth_state;

    /* our current blob to pass to the client */
    char *server_blob;
    /* our current blob to pass to the server */
    char *client_blob;

    /* currently waiting for helper response */
    unsigned char waiting;

    /* need access to the request flags to mess around on pconn failure */
    HttpRequest *request;
};

MEMPROXY_CLASS_INLINE(AuthNegotiateUserRequest);

/* configuration runtime data */

/// \ingroup AuthNegotiateAPI
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
    virtual void registerWithCacheManager(void);
    virtual const char * type() const;
    int authenticateChildren;
    int keep_alive;
    wordlist *authenticate;
};

/// \ingroup AuthNegotiateAPI
typedef class AuthNegotiateConfig auth_negotiate_config;

#endif
