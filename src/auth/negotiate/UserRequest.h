#ifndef _SQUID_SRC_AUTH_NEGOTIATE_USERREQUEST_H
#define _SQUID_SRC_AUTH_NEGOTIATE_USERREQUEST_H

#include "auth/UserRequest.h"
#include "helper.h"
#include "MemPool.h"

class ConnStateData;
class HttpReply;
class HttpRequest;
struct helper_stateful_server;

/// \ingroup AuthNegotiateAPI
class AuthNegotiateUserRequest : public AuthUserRequest
{

public:
    MEMPROXY_CLASS(AuthNegotiateUserRequest);

    AuthNegotiateUserRequest();
    virtual ~AuthNegotiateUserRequest();
    virtual int authenticated() const;
    virtual void authenticate(HttpRequest * request, ConnStateData * conn, http_hdr_type type);
    virtual Auth::Direction module_direction();
    virtual void onConnectionClose(ConnStateData *);
    virtual void module_start(RH *, void *);

    virtual void addHeader(HttpReply * rep, int accel);

    virtual const char * connLastHeader();

    /* we need to store the helper server between requests */
    helper_stateful_server *authserver;
    void releaseAuthServer(void); ///< Release the authserver helper server properly.

    /* what connection is this associated with */
    /* ConnStateData * conn;*/

    /* our current blob to pass to the client */
    char *server_blob;
    /* our current blob to pass to the server */
    char *client_blob;

    /* currently waiting for helper response */
    unsigned char waiting;

    /* need access to the request flags to mess around on pconn failure */
    HttpRequest *request;

private:
    static HLPSCB HandleReply;
};

MEMPROXY_CLASS_INLINE(AuthNegotiateUserRequest);

#endif /* _SQUID_SRC_AUTH_NEGOTIATE_USERREQUEST_H */
