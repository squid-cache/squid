#ifndef _SQUID_SRC_AUTH_DIGEST_USERREQUEST_H
#define _SQUID_SRC_AUTH_DIGEST_USERREQUEST_H

#include "auth/UserRequest.h"
#include "auth/digest/auth_digest.h"
#include "MemPool.h"

class ConnStateData;
class HttpReply;
class HttpRequest;

/**
 * The AuthDigestUserRequest structure is what follows the http_request around
 */
class AuthDigestUserRequest : public AuthUserRequest
{

public:
    MEMPROXY_CLASS(AuthDigestUserRequest);

    AuthDigestUserRequest();
    virtual ~AuthDigestUserRequest();

    virtual int authenticated() const;
    virtual void authenticate(HttpRequest * request, ConnStateData * conn, http_hdr_type type);
    virtual int module_direction();
    virtual void addHeader(HttpReply * rep, int accel);
#if WAITING_FOR_TE

    virtual void addTrailer(HttpReply * rep, int accel);
#endif

    virtual void module_start(RH *, void *);

    char *nonceb64;             /* "dcd98b7102dd2f0e8b11d0f600bfb0c093" */
    char *cnonce;               /* "0a4f113b" */
    char *realm;                /* = "testrealm@host.com" */
    char *pszPass;              /* = "Circle Of Life" */
    char *algorithm;            /* = "md5" */
    char nc[9];                 /* = "00000001" */
    char *pszMethod;            /* = "GET" */
    char *qop;                  /* = "auth" */
    char *uri;                  /* = "/dir/index.html" */
    char *response;

    struct {
        unsigned int authinfo_sent:1;
        unsigned int invalid_password:1;
        unsigned int helper_queried:1;
    } flags;
    digest_nonce_h *nonce;

private:
    static HLPCB HandleReply;
};

MEMPROXY_CLASS_INLINE(AuthDigestUserRequest);

#endif /* _SQUID_SRC_AUTH_DIGEST_USERREQUEST_H */
