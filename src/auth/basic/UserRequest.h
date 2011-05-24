#ifndef _SQUID_SRC_AUTH_BASIC_USERREQUEST_H
#define _SQUID_SRC_AUTH_BASIC_USERREQUEST_H

#include "MemPool.h"
#include "auth/UserRequest.h"

class ConnStateData;
class HttpRequest;

/* follows the http request around */

class AuthBasicUserRequest : public AuthUserRequest
{

public:
    MEMPROXY_CLASS(AuthBasicUserRequest);

    AuthBasicUserRequest() {};
    virtual ~AuthBasicUserRequest() { assert(RefCountCount()==0); };

    virtual int authenticated() const;
    virtual void authenticate(HttpRequest * request, ConnStateData *conn, http_hdr_type type);
    virtual Auth::Direction module_direction();
    virtual void module_start(RH *, void *);
};

MEMPROXY_CLASS_INLINE(AuthBasicUserRequest);

#endif /* _SQUID_SRC_AUTH_BASIC_USERREQUEST_H */
