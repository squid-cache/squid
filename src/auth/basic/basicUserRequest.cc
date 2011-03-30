#include "config.h"
#include "auth/basic/basicUserRequest.h"
#include "SquidTime.h"

#include "auth/basic/auth_basic.h"

int
AuthBasicUserRequest::authenticated() const
{
    BasicUser const *basic_auth = dynamic_cast<BasicUser const *>(user().getRaw());

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
    if (!user() || user()->credentials() != AuthUser::Ok)
        return;

    /* are we about to recheck the credentials externally? */
    if ((user()->expiretime + static_cast<AuthBasicConfig*>(AuthConfig::Find("basic"))->credentialsTTL) <= squid_curtime) {
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
    if (user()->auth_type != AUTH_BASIC)
        return -2;

    switch (user()->credentials()) {

    case AuthUser::Unchecked:
    case AuthUser::Pending:
        return -1;

    case AuthUser::Ok:
        if (user()->expiretime + static_cast<AuthBasicConfig*>(AuthConfig::Find("basic"))->credentialsTTL <= squid_curtime)
            return -1;
        return 0;

    case AuthUser::Failed:
        return 0;

    default:
        return -2;
    }
}

/* send the initial data to a basic authenticator module */
void
AuthBasicUserRequest::module_start(RH * handler, void *data)
{
    assert(user()->auth_type == AUTH_BASIC);
    BasicUser *basic_auth = dynamic_cast<BasicUser *>(user().getRaw());
    assert(basic_auth != NULL);
    debugs(29, 9, HERE << "'" << basic_auth->username() << ":" << basic_auth->passwd << "'");

    if (static_cast<AuthBasicConfig*>(AuthConfig::Find("basic"))->authenticateProgram == NULL) {
        debugs(29, DBG_CRITICAL, "ERROR: No Basic authentication program configured.");
        handler(data, NULL);
        return;
    }

    /* check to see if the auth_user already has a request outstanding */
    if (user()->credentials() == AuthUser::Pending) {
        /* there is a request with the same credentials already being verified */
        basic_auth->queueRequest(this, handler, data);
        return;
    }

    basic_auth->submitRequest(this, handler, data);
}

