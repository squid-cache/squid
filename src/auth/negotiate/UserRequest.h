/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_NEGOTIATE_USERREQUEST_H
#define SQUID_SRC_AUTH_NEGOTIATE_USERREQUEST_H

#if HAVE_AUTH_MODULE_NEGOTIATE

#include "auth/UserRequest.h"
#include "helper/forward.h"
#include "helper/ReservationId.h"

class ConnStateData;
class HttpReply;
class HttpRequest;

namespace Auth
{
namespace Negotiate
{

class UserRequest : public Auth::UserRequest
{
    MEMPROXY_CLASS(Auth::Negotiate::UserRequest);

public:
    UserRequest();
    ~UserRequest() override;
    int authenticated() const override;
    void authenticate(HttpRequest * request, ConnStateData * conn, Http::HdrType type) override;
    Direction module_direction() override;
    void startHelperLookup(HttpRequest *request, AccessLogEntry::Pointer &al, AUTHCB *, void *) override;
    const char *credentialsStr() override;

    const char * connLastHeader() override;

    void releaseAuthServer(void) override; ///< Release the authserver helper server properly.

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

    /// a helper-issued reservation locking the helper state between
    /// HTTP requests
    Helper::ReservationId reservationId;
private:
    static HLPCB HandleReply;
};

} // namespace Negotiate
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_NEGOTIATE */
#endif /* SQUID_SRC_AUTH_NEGOTIATE_USERREQUEST_H */

