#ifndef _SQUID_SRC_AUTH_NTLM_USERREQUEST_H
#define _SQUID_SRC_AUTH_NTLM_USERREQUEST_H

#include "auth/UserRequest.h"
#include "auth/ntlm/auth_ntlm.h"
#include "MemPool.h"

class ConnStateData;
class HttpReply;
class HttpRequest;
class helper_stateful_server;

namespace Auth
{
namespace Ntlm
{

class UserRequest : public Auth::UserRequest
{

public:
    MEMPROXY_CLASS(Auth::Ntlm::UserRequest);

    UserRequest();
    virtual ~UserRequest();
    virtual int authenticated() const;
    virtual void authenticate(HttpRequest * request, ConnStateData * conn, http_hdr_type type);
    virtual Auth::Direction module_direction();
    virtual void module_start(AUTHCB *, void *);

    virtual const char * connLastHeader();

    /* we need to store the helper server between requests */
    helper_stateful_server *authserver;
    virtual void releaseAuthServer(); ///< Release authserver NTLM helpers properly when finished or abandoning.

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

} // namespace Ntlm
} // namespace Auth

MEMPROXY_CLASS_INLINE(Auth::Ntlm::UserRequest);

#endif /* _SQUID_SRC_AUTH_NTLM_USERREQUEST_H */
