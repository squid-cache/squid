#ifndef _SQUID_SRC_AUTH_NTLM_USERREQUEST_H
#define _SQUID_SRC_AUTH_NTLM_USERREQUEST_H

#include "auth/UserRequest.h"
#include "auth/ntlm/auth_ntlm.h"
#include "MemPool.h"

class ConnStateData;
class HttpReply;
class HttpRequest;
struct helper_stateful_server;

class AuthNTLMUserRequest : public AuthUserRequest
{

public:
    MEMPROXY_CLASS(AuthNTLMUserRequest);

    AuthNTLMUserRequest();
    virtual ~AuthNTLMUserRequest();
    virtual int authenticated() const;
    virtual void authenticate(HttpRequest * request, ConnStateData * conn, http_hdr_type type);
    virtual int module_direction();
    virtual void onConnectionClose(ConnStateData *);
    virtual void module_start(RH *, void *);

    virtual const char * connLastHeader();

    /* we need to store the helper server between requests */
    helper_stateful_server *authserver;
    void releaseAuthServer(void); ///< Release authserver NTLM helpers properly when finished or abandoning.

    /* what connection is this associated with */
//    ConnStateData * conn;

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

MEMPROXY_CLASS_INLINE(AuthNTLMUserRequest);

#endif /* _SQUID_SRC_AUTH_NTLM_USERREQUEST_H */
