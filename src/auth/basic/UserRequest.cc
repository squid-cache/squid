#include "config.h"
#include "auth/basic/auth_basic.h"
#include "auth/basic/User.h"
#include "auth/basic/UserRequest.h"
#include "SquidTime.h"

int
AuthBasicUserRequest::authenticated() const
{
    Auth::Basic::User const *basic_auth = dynamic_cast<Auth::Basic::User const *>(user().getRaw());

    if (basic_auth && basic_auth->authenticated())
        return 1;

    return 0;
}

/* log a basic user in
 */
void
AuthBasicUserRequest::authenticate(HttpRequest * request, ConnStateData * conn, http_hdr_type type)
{
    assert(user() != NULL);

    /* if the password is not ok, do an identity */
    if (!user() || user()->credentials() != Auth::Ok)
        return;

    /* are we about to recheck the credentials externally? */
    if ((user()->expiretime + static_cast<Auth::Basic::Config*>(Auth::Config::Find("basic"))->credentialsTTL) <= squid_curtime) {
        debugs(29, 4, HERE << "credentials expired - rechecking");
        return;
    }

    /* we have been through the external helper, and the credentials haven't expired */
    debugs(29, 9, HERE << "user '" << user()->username() << "' authenticated");

    /* Decode now takes care of finding the AuthUser struct in the cache */
    /* after external auth occurs anyway */
    user()->expiretime = current_time.tv_sec;

    return;
}

int
AuthBasicUserRequest::module_direction()
{
    /* null auth_user is checked for by authenticateDirection */
    if (user()->auth_type != Auth::AUTH_BASIC)
        return -2;

    switch (user()->credentials()) {

    case Auth::Unchecked:
    case Auth::Pending:
        return -1;

    case Auth::Ok:
        if (user()->expiretime + static_cast<Auth::Basic::Config*>(Auth::Config::Find("basic"))->credentialsTTL <= squid_curtime)
            return -1;
        return 0;

    case Auth::Failed:
        return 0;

    default:
        return -2;
    }
}

/* send the initial data to a basic authenticator module */
void
AuthBasicUserRequest::module_start(RH * handler, void *data)
{
    assert(user()->auth_type == Auth::AUTH_BASIC);
    Auth::Basic::User *basic_auth = dynamic_cast<Auth::Basic::User *>(user().getRaw());
    assert(basic_auth != NULL);
    debugs(29, 9, HERE << "'" << basic_auth->username() << ":" << basic_auth->passwd << "'");

    if (static_cast<Auth::Basic::Config*>(Auth::Config::Find("basic"))->authenticateProgram == NULL) {
        debugs(29, DBG_CRITICAL, "ERROR: No Basic authentication program configured.");
        handler(data, NULL);
        return;
    }

    /* check to see if the auth_user already has a request outstanding */
    if (user()->credentials() == Auth::Pending) {
        /* there is a request with the same credentials already being verified */
        basic_auth->queueRequest(this, handler, data);
        return;
    }

    basic_auth->submitRequest(this, handler, data);
}

