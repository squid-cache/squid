#include "config.h"
#include "auth/ntlm/auth_ntlm.h"
#include "auth/ntlm/UserRequest.h"
#include "auth/State.h"
#include "cbdata.h"
#include "HttpRequest.h"
#include "SquidTime.h"

/* state wrapper functions */

AuthNTLMUserRequest::AuthNTLMUserRequest()
{
    waiting=0;
    client_blob=0;
    server_blob=0;
    authserver=NULL;
    request = NULL;
}

AuthNTLMUserRequest::~AuthNTLMUserRequest()
{
    assert(RefCountCount()==0);
    safe_free(server_blob);
    safe_free(client_blob);

    releaseAuthServer();

    if (request) {
        HTTPMSGUNLOCK(request);
        request = NULL;
    }
}

const char *
AuthNTLMUserRequest::connLastHeader()
{
    return NULL;
}

/* See AuthUserRequest.cc::authenticateDirection for return values */
int
AuthNTLMUserRequest::module_direction()
{
    /* null auth_user is checked for by authenticateDirection */

    if (waiting || client_blob)
        return -1; /* need helper response to continue */

    if (user()->auth_type != Auth::AUTH_NTLM)
        return -2;

    switch (user()->credentials()) {

    case AuthUser::Handshake:
        assert(server_blob);
        return 1; /* send to client */

    case AuthUser::Ok:
        return 0; /* do nothing */

    case AuthUser::Failed:
        return -2;

    default:
        debugs(29, DBG_IMPORTANT, "WARNING: NTLM Authentication in unexpected state: " << user()->credentials());
        return -2;
    }
}

/* send the initial data to a stateful ntlm authenticator module */
void
AuthNTLMUserRequest::module_start(RH * handler, void *data)
{
    authenticateStateData *r = NULL;
    static char buf[8192];

    assert(data);
    assert(handler);

    debugs(29, 8, HERE << "credentials state is '" << user()->credentials() << "'");

    if (static_cast<AuthNTLMConfig*>(AuthConfig::Find("ntlm"))->authenticateProgram == NULL) {
        debugs(29, DBG_CRITICAL, "ERROR: NTLM Start: no NTLM program configured.");
        handler(data, NULL);
        return;
    }

    r = cbdataAlloc(authenticateStateData);
    r->handler = handler;
    r->data = cbdataReference(data);
    r->auth_user_request = this;

    if (user()->credentials() == AuthUser::Pending) {
        snprintf(buf, 8192, "YR %s\n", client_blob); //CHECKME: can ever client_blob be 0 here?
    } else {
        snprintf(buf, 8192, "KK %s\n", client_blob);
    }

    waiting = 1;

    safe_free(client_blob);
    helperStatefulSubmit(ntlmauthenticators, buf, AuthNTLMUserRequest::HandleReply, r, authserver);
}

/**
 * Atomic action: properly release the NTLM auth helpers which may have been reserved
 * for this request connections use.
 */
void
AuthNTLMUserRequest::releaseAuthServer()
{
    if (authserver) {
        debugs(29, 6, HERE << "releasing NTLM auth server '" << authserver << "'");
        helperStatefulReleaseServer(authserver);
        authserver = NULL;
    } else
        debugs(29, 6, HERE << "No NTLM auth server to release.");
}

void
AuthNTLMUserRequest::onConnectionClose(ConnStateData *conn)
{
    assert(conn != NULL);

    debugs(29, 8, "AuthNTLMUserRequest::onConnectionClose: closing connection '" << conn << "' (this is '" << this << "')");

    if (conn->auth_user_request == NULL) {
        debugs(29, 8, "AuthNTLMUserRequest::onConnectionClose: no auth_user_request");
        return;
    }

    // unlock / un-reserve the helpers
    releaseAuthServer();

    /* unlock the connection based lock */
    debugs(29, 9, "AuthNTLMUserRequest::onConnectionClose: Unlocking auth_user from the connection '" << conn << "'.");

    conn->auth_user_request = NULL;
}

int
AuthNTLMUserRequest::authenticated() const
{
    if (user()->credentials() == AuthUser::Ok) {
        debugs(29, 9, "AuthNTLMUserRequest::authenticated: user authenticated.");
        return 1;
    }

    debugs(29, 9, "AuthNTLMUserRequest::authenticated: user not fully authenticated.");

    return 0;
}

void
AuthNTLMUserRequest::authenticate(HttpRequest * aRequest, ConnStateData * conn, http_hdr_type type)
{
    const char *proxy_auth, *blob;

    assert(this);

    /* Check that we are in the client side, where we can generate
     * auth challenges */

    if (conn == NULL || !cbdataReferenceValid(conn)) {
        user()->credentials(AuthUser::Failed);
        debugs(29, 1, "AuthNTLMUserRequest::authenticate: attempt to perform authentication without a connection!");
        return;
    }

    if (waiting) {
        debugs(29, 1, "AuthNTLMUserRequest::authenticate: waiting for helper reply!");
        return;
    }

    if (server_blob) {
        debugs(29, 2, "AuthNTLMUserRequest::authenticate: need to challenge client '" << server_blob << "'!");
        return;
    }

    /* get header */
    proxy_auth = aRequest->header.getStr(type);

    /* locate second word */
    blob = proxy_auth;

    /* if proxy_auth is actually NULL, we'd better not manipulate it. */
    if (blob) {
        while (xisspace(*blob) && *blob)
            blob++;

        while (!xisspace(*blob) && *blob)
            blob++;

        while (xisspace(*blob) && *blob)
            blob++;
    }

    switch (user()->credentials()) {

    case AuthUser::Unchecked:
        /* we've received a ntlm request. pass to a helper */
        debugs(29, 9, "AuthNTLMUserRequest::authenticate: auth state ntlm none. Received blob: '" << proxy_auth << "'");
        user()->credentials(AuthUser::Pending);
        safe_free(client_blob);
        client_blob=xstrdup(blob);
        assert(conn->auth_user_request == NULL);
        conn->auth_user_request = this;
        request = aRequest;
        HTTPMSGLOCK(request);
        break;

    case AuthUser::Pending:
        debugs(29, 1, "AuthNTLMUserRequest::authenticate: need to ask helper");
        break;

    case AuthUser::Handshake:
        /* we should have received a blob from the client. Hand it off to
         * some helper */
        safe_free(client_blob);
        client_blob = xstrdup (blob);

        if (request)
            HTTPMSGUNLOCK(request);
        request = aRequest;
        HTTPMSGLOCK(request);
        break;

    case AuthUser::Ok:
        fatal("AuthNTLMUserRequest::authenticate: unexpect auth state DONE! Report a bug to the squid developers.\n");
        break;

    case AuthUser::Failed:
        /* we've failed somewhere in authentication */
        debugs(29, 9, "AuthNTLMUserRequest::authenticate: auth state ntlm failed. " << proxy_auth);
        break;
    }
}

void
AuthNTLMUserRequest::HandleReply(void *data, void *lastserver, char *reply)
{
    authenticateStateData *r = static_cast<authenticateStateData *>(data);

    int valid;
    char *blob;

    debugs(29, 8, "authenticateNTLMHandleReply: helper: '" << lastserver << "' sent us '" << (reply ? reply : "<NULL>") << "'");
    valid = cbdataReferenceValid(r->data);

    if (!valid) {
        debugs(29, 1, "authenticateNTLMHandleReply: invalid callback data. helper '" << lastserver << "'.");
        cbdataReferenceDone(r->data);
        authenticateStateFree(r);
        return;
    }

    if (!reply) {
        debugs(29, 1, "authenticateNTLMHandleReply: Helper '" << lastserver << "' crashed!.");
        reply = (char *)"BH Internal error";
    }

    AuthUserRequest::Pointer auth_user_request = r->auth_user_request;
    assert(auth_user_request != NULL);

    AuthNTLMUserRequest *ntlm_request = dynamic_cast<AuthNTLMUserRequest *>(auth_user_request.getRaw());
    assert(ntlm_request != NULL);
    assert(ntlm_request->waiting);
    assert(ntlm_request->user() != NULL);
    assert(ntlm_request->user()->auth_type == Auth::AUTH_NTLM);

    ntlm_request->waiting = 0;
    safe_free(ntlm_request->client_blob);

    if (ntlm_request->authserver == NULL)
        ntlm_request->authserver = static_cast<helper_stateful_server*>(lastserver);
    else
        assert(ntlm_request->authserver == lastserver);

    /* seperate out the useful data */
    blob = strchr(reply, ' ');
    if (blob)
        blob++;

    if (strncasecmp(reply, "TT ", 3) == 0) {
        /* we have been given a blob to send to the client */
        safe_free(ntlm_request->server_blob);
        ntlm_request->request->flags.must_keepalive = 1;
        if (ntlm_request->request->flags.proxy_keepalive) {
            ntlm_request->server_blob = xstrdup(blob);
            ntlm_request->user()->credentials(AuthUser::Handshake);
            auth_user_request->denyMessage("Authentication in progress");
            debugs(29, 4, "authenticateNTLMHandleReply: Need to challenge the client with a server blob '" << blob << "'");
        } else {
            ntlm_request->user()->credentials(AuthUser::Failed);
            auth_user_request->denyMessage("NTLM authentication requires a persistent connection");
        }
    } else if (strncasecmp(reply, "AF ", 3) == 0) {
        /* we're finished, release the helper */
        auth_user_request->user()->username(blob);
        auth_user_request->denyMessage("Login successful");
        safe_free(ntlm_request->server_blob);

        debugs(29, 4, "authenticateNTLMHandleReply: Successfully validated user via NTLM. Username '" << blob << "'");
        /* connection is authenticated */
        debugs(29, 4, "AuthNTLMUserRequest::authenticate: authenticated user " << auth_user_request->user()->username());
        /* see if this is an existing user with a different proxy_auth
         * string */
        auth_user_hash_pointer *usernamehash = static_cast<AuthUserHashPointer *>(hash_lookup(proxy_auth_username_cache, auth_user_request->user()->username()));
        AuthUser::Pointer local_auth_user = ntlm_request->user();
        while (usernamehash && (usernamehash->user()->auth_type != Auth::AUTH_NTLM ||
                                strcmp(usernamehash->user()->username(), auth_user_request->user()->username()) != 0))
            usernamehash = static_cast<AuthUserHashPointer *>(usernamehash->next);
        if (usernamehash) {
            /* we can't seamlessly recheck the username due to the
             * challenge-response nature of the protocol.
             * Just free the temporary auth_user */
            usernamehash->user()->absorb(local_auth_user);
            local_auth_user = usernamehash->user();
            ntlm_request->_auth_user = local_auth_user;
        } else {
            /* store user in hash's */
            local_auth_user->addToNameCache();
        }
        /* set these to now because this is either a new login from an
         * existing user or a new user */
        local_auth_user->expiretime = current_time.tv_sec;
        ntlm_request->releaseAuthServer();
        local_auth_user->credentials(AuthUser::Ok);
    } else if (strncasecmp(reply, "NA ", 3) == 0) {
        /* authentication failure (wrong password, etc.) */
        auth_user_request->denyMessage(blob);
        ntlm_request->user()->credentials(AuthUser::Failed);
        safe_free(ntlm_request->server_blob);
        ntlm_request->releaseAuthServer();
        debugs(29, 4, "authenticateNTLMHandleReply: Failed validating user via NTLM. Error returned '" << blob << "'");
    } else if (strncasecmp(reply, "BH ", 3) == 0) {
        /* TODO kick off a refresh process. This can occur after a YR or after
         * a KK. If after a YR release the helper and resubmit the request via
         * Authenticate NTLM start.
         * If after a KK deny the user's request w/ 407 and mark the helper as
         * Needing YR. */
        auth_user_request->denyMessage(blob);
        auth_user_request->user()->credentials(AuthUser::Failed);
        safe_free(ntlm_request->server_blob);
        ntlm_request->releaseAuthServer();
        debugs(29, 1, "authenticateNTLMHandleReply: Error validating user via NTLM. Error returned '" << reply << "'");
    } else {
        /* protocol error */
        fatalf("authenticateNTLMHandleReply: *** Unsupported helper response ***, '%s'\n", reply);
    }

    if (ntlm_request->request) {
        HTTPMSGUNLOCK(ntlm_request->request);
        ntlm_request->request = NULL;
    }
    r->handler(r->data, NULL);
    cbdataReferenceDone(r->data);
    authenticateStateFree(r);
}
