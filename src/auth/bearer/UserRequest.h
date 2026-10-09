/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_AUTH_BEARER_USERREQUEST_H
#define _SQUID_SRC_AUTH_BEARER_USERREQUEST_H

#if HAVE_AUTH_MODULE_BEARER

#include "auth/UserRequest.h"
#include "http/forward.h"
#include "servers/forward.h"

namespace Auth
{
namespace Bearer
{

class UserRequest : public Auth::UserRequest
{
    MEMPROXY_CLASS(Auth::Bearer::UserRequest);

public:
    /* Auth::UserRequest API */
    int authenticated() const override;
    void authenticate(HttpRequest *, ConnStateData *, Http::HdrType) override;
    Direction module_direction() override;
    void startHelperLookup(HttpRequest *, AccessLogEntry::Pointer &, AUTHCB *, void *) override;
    const char *credentialsStr() override;

private:
    static HLPCB HandleReply;
};

} // namespace Bearer
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_BEARER */
#endif /* _SQUID_SRC_AUTH_BEARER_USERREQUEST_H */
