#ifndef _SQUID_SRC_AUTH_NEGOTIATE_USERREQUEST_H
#define _SQUID_SRC_AUTH_NEGOTIATE_USERREQUEST_H

#include "auth/UserRequest.h"
#include "MemPool.h"

class ConnStateData;
class HttpReply;
class HttpRequest;
class helper_stateful_server;

namespace Auth
{
namespace Negotiate
{

/// \ingroup AuthNegotiateAPI
class UserRequest : public Auth::UserRequest
{

public:
    MEMPROXY_CLASS(Auth::Negotiate::UserRequest);

    UserRequest();
    virtual ~UserRequest();
    virtual int authenticated() const;
    virtual void authenticate(HttpRequest * request, ConnStateData * conn, http_hdr_type type);
    virtual Direction module_direction();
    virtual void module_start(AUTHCB *, void *);

    virtual void addAuthenticationInfoHeader(HttpReply * rep, int accel);

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
    static HLPCB HandleReply;
};

} // namespace Negotiate
} // namespace Auth

MEMPROXY_CLASS_INLINE(Auth::Negotiate::UserRequest);

#endif /* _SQUID_SRC_AUTH_NEGOTIATE_USERREQUEST_H */
