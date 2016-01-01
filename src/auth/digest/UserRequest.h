/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_AUTH_DIGEST_USERREQUEST_H
#define _SQUID_SRC_AUTH_DIGEST_USERREQUEST_H

#if HAVE_AUTH_MODULE_DIGEST

#include "auth/UserRequest.h"

class ConnStateData;
class HttpReply;
class HttpRequest;

namespace Auth
{
namespace Digest
{

/**
 * The UserRequest structure is what follows the http_request around
 */
class UserRequest : public Auth::UserRequest
{
    MEMPROXY_CLASS(Auth::Digest::UserRequest);

public:
    UserRequest();
    virtual ~UserRequest();

    virtual int authenticated() const;
    virtual void authenticate(HttpRequest * request, ConnStateData * conn, Http::HdrType type);
    virtual Direction module_direction();
    virtual void addAuthenticationInfoHeader(HttpReply * rep, int accel);
#if WAITING_FOR_TE
    virtual void addAuthenticationInfoTrailer(HttpReply * rep, int accel);
#endif

    virtual void startHelperLookup(HttpRequest *request, AccessLogEntry::Pointer &al, AUTHCB *, void *);
    virtual const char *credentialsStr();

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
        bool authinfo_sent;
        bool invalid_password;
        bool helper_queried;
    } flags;
    digest_nonce_h *nonce;

private:
    static HLPCB HandleReply;
};

} // namespace Digest
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_DIGEST */
#endif /* _SQUID_SRC_AUTH_DIGEST_USERREQUEST_H */

