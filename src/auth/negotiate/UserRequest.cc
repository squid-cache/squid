#include "squid.h"
#include "auth/negotiate/auth_negotiate.h"
#include "auth/negotiate/UserRequest.h"
#include "auth/State.h"
#include "auth/User.h"
#include "client_side.h"
#include "globals.h"
#include "helper.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "SquidTime.h"

Auth::Negotiate::UserRequest::UserRequest()
{
    waiting=0;
    client_blob=0;
    server_blob=0;
    authserver=NULL;
    request=NULL;
}

Auth::Negotiate::UserRequest::~UserRequest()
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
Auth::Negotiate::UserRequest::connLastHeader()
{
    return NULL;
}

int
Auth::Negotiate::UserRequest::authenticated() const
{
    if (user() != NULL && user()->credentials() == Auth::Ok) {
        debugs(29, 9, HERE << "user authenticated.");
        return 1;
    }

    debugs(29, 9, HERE << "user not fully authenticated.");
    return 0;
}

Auth::Direction
Auth::Negotiate::UserRequest::module_direction()
{
    /* null auth_user is checked for by Auth::UserRequest::direction() */

    if (waiting || client_blob)
        return Auth::CRED_LOOKUP; /* need helper response to continue */

    if (user()->auth_type != Auth::AUTH_NEGOTIATE)
        return Auth::CRED_ERROR;

    switch (user()->credentials()) {

    case Auth::Handshake:
        assert(server_blob);
        return Auth::CRED_CHALLENGE;

    case Auth::Ok:
        return Auth::CRED_VALID;

    case Auth::Failed:
        return Auth::CRED_ERROR; // XXX: really? not VALID or CHALLENGE?

    default:
        debugs(29, DBG_IMPORTANT, "WARNING: Negotiate Authentication in unexpected state: " << user()->credentials());
        return Auth::CRED_ERROR;
    }
}

void
Auth::Negotiate::UserRequest::module_start(AUTHCB * handler, void *data)
{
    static char buf[MAX_AUTHTOKEN_LEN];

    assert(data);
    assert(handler);

    assert(user() != NULL);
    assert(user()->auth_type == Auth::AUTH_NEGOTIATE);

    if (static_cast<Auth::Negotiate::Config*>(Auth::Config::Find("negotiate"))->authenticateProgram == NULL) {
        debugs(29, DBG_CRITICAL, "ERROR: No Negotiate authentication program configured.");
        handler(data);
        return;
    }

    debugs(29, 8, HERE << "credentials state is '" << user()->credentials() << "'");

    if (user()->credentials() == Auth::Pending) {
        snprintf(buf, sizeof(buf), "YR %s\n", client_blob); //CHECKME: can ever client_blob be 0 here?
    } else {
        snprintf(buf, sizeof(buf), "KK %s\n", client_blob);
    }

    waiting = 1;

    safe_free(client_blob);

    helperStatefulSubmit(negotiateauthenticators, buf, Auth::Negotiate::UserRequest::HandleReply,
                         new Auth::StateData(this, handler, data), authserver);
}

/**
 * Atomic action: properly release the Negotiate auth helpers which may have been reserved
 * for this request connections use.
 */
void
Auth::Negotiate::UserRequest::releaseAuthServer()
{
    if (authserver) {
        debugs(29, 6, HERE << "releasing Negotiate auth server '" << authserver << "'");
        helperStatefulReleaseServer(authserver);
        authserver = NULL;
    } else
        debugs(29, 6, HERE << "No Negotiate auth server to release.");
}

/* clear any connection related authentication details */
void
Auth::Negotiate::UserRequest::onConnectionClose(ConnStateData *conn)
{
    assert(conn != NULL);

    debugs(29, 8, HERE << "closing connection '" << conn << "' (this is '" << this << "')");

    if (conn->auth_user_request == NULL) {
        debugs(29, 8, HERE << "no auth_user_request");
        return;
    }

    releaseAuthServer();

    /* unlock the connection based lock */
    debugs(29, 9, HERE << "Unlocking auth_user from the connection '" << conn << "'.");

    conn->auth_user_request = NULL;
}

void
Auth::Negotiate::UserRequest::authenticate(HttpRequest * aRequest, ConnStateData * conn, http_hdr_type type)
{
    assert(this);

    /* Check that we are in the client side, where we can generate
     * auth challenges */

    if (conn == NULL || !cbdataReferenceValid(conn)) {
        user()->credentials(Auth::Failed);
        debugs(29, DBG_IMPORTANT, "WARNING: Negotiate Authentication attempt to perform authentication without a connection!");
        return;
    }

    if (waiting) {
        debugs(29, DBG_IMPORTANT, "WARNING: Negotiate Authentication waiting for helper reply!");
        return;
    }

    if (server_blob) {
        debugs(29, 2, HERE << "need to challenge client '" << server_blob << "'!");
        return;
    }

    /* get header */
    const char *proxy_auth = aRequest->header.getStr(type);

    /* locate second word */
    const char *blob = proxy_auth;

    if (blob) {
        while (xisspace(*blob) && *blob)
            ++blob;

        while (!xisspace(*blob) && *blob)
            ++blob;

        while (xisspace(*blob) && *blob)
            ++blob;
    }

    switch (user()->credentials()) {

    case Auth::Unchecked:
        /* we've received a negotiate request. pass to a helper */
        debugs(29, 9, HERE << "auth state negotiate none. Received blob: '" << proxy_auth << "'");
        user()->credentials(Auth::Pending);
        safe_free(client_blob);
        client_blob=xstrdup(blob);
        assert(conn->auth_user_request == NULL);
        conn->auth_user_request = this;
        request = aRequest;
        HTTPMSGLOCK(request);
        break;

    case Auth::Pending:
        debugs(29, DBG_IMPORTANT, HERE << "need to ask helper");
        break;

    case Auth::Handshake:
        /* we should have received a blob from the client. Hand it off to
         * some helper */
        safe_free(client_blob);
        client_blob = xstrdup(blob);
        if (request)
            HTTPMSGUNLOCK(request);
        request = aRequest;
        HTTPMSGLOCK(request);
        break;

    case Auth::Ok:
        fatal("Auth::Negotiate::UserRequest::authenticate: unexpected auth state DONE! Report a bug to the squid developers.\n");
        break;

    case Auth::Failed:
        /* we've failed somewhere in authentication */
        debugs(29, 9, HERE << "auth state negotiate failed. " << proxy_auth);
        break;
    }
}

void
Auth::Negotiate::UserRequest::HandleReply(void *data, void *lastserver, char *reply)
{
    Auth::StateData *r = static_cast<Auth::StateData *>(data);

    char *blob, *arg = NULL;

    debugs(29, 8, HERE << "helper: '" << lastserver << "' sent us '" << (reply ? reply : "<NULL>") << "'");

    if (!cbdataReferenceValid(r->data)) {
        debugs(29, DBG_IMPORTANT, "ERROR: Negotiate Authentication invalid callback data. helper '" << lastserver << "'.");
        delete r;
        return;
    }

    if (!reply) {
        debugs(29, DBG_IMPORTANT, "ERROR: Negotiate Authentication Helper '" << lastserver << "' crashed!.");
        reply = (char *)"BH Internal error";
    }

    Auth::UserRequest::Pointer auth_user_request = r->auth_user_request;
    assert(auth_user_request != NULL);

    Auth::Negotiate::UserRequest *lm_request = dynamic_cast<Auth::Negotiate::UserRequest *>(auth_user_request.getRaw());
    assert(lm_request != NULL);
    assert(lm_request->waiting);

    lm_request->waiting = 0;
    safe_free(lm_request->client_blob);

    assert(auth_user_request->user() != NULL);
    assert(auth_user_request->user()->auth_type == Auth::AUTH_NEGOTIATE);

    if (lm_request->authserver == NULL)
        lm_request->authserver = static_cast<helper_stateful_server*>(lastserver);
    else
        assert(lm_request->authserver == lastserver);

    /* seperate out the useful data */
    blob = strchr(reply, ' ');

    if (blob) {
        ++blob;
        arg = strchr(blob + 1, ' ');
    } else {
        arg = NULL;
    }

    if (strncasecmp(reply, "TT ", 3) == 0) {
        /* we have been given a blob to send to the client */
        if (arg) {
            *arg = '\0';
            ++arg;
        }
        safe_free(lm_request->server_blob);
        lm_request->request->flags.mustKeepalive = 1;
        if (lm_request->request->flags.proxyKeepalive) {
            lm_request->server_blob = xstrdup(blob);
            auth_user_request->user()->credentials(Auth::Handshake);
            auth_user_request->denyMessage("Authentication in progress");
            debugs(29, 4, HERE << "Need to challenge the client with a server blob '" << blob << "'");
        } else {
            auth_user_request->user()->credentials(Auth::Failed);
            auth_user_request->denyMessage("NTLM authentication requires a persistent connection");
        }
    } else if (strncasecmp(reply, "AF ", 3) == 0 && arg != NULL) {
        /* we're finished, release the helper */

        if (arg) {
            *arg = '\0';
            ++arg;
        }

        auth_user_request->user()->username(arg);
        auth_user_request->denyMessage("Login successful");
        safe_free(lm_request->server_blob);
        lm_request->server_blob = xstrdup(blob);
        lm_request->releaseAuthServer();

        /* connection is authenticated */
        debugs(29, 4, HERE << "authenticated user " << auth_user_request->user()->username());
        /* see if this is an existing user with a different proxy_auth
         * string */
        AuthUserHashPointer *usernamehash = static_cast<AuthUserHashPointer *>(hash_lookup(proxy_auth_username_cache, auth_user_request->user()->username()));
        Auth::User::Pointer local_auth_user = lm_request->user();
        while (usernamehash && (usernamehash->user()->auth_type != Auth::AUTH_NEGOTIATE ||
                                strcmp(usernamehash->user()->username(), auth_user_request->user()->username()) != 0))
            usernamehash = static_cast<AuthUserHashPointer *>(usernamehash->next);
        if (usernamehash) {
            /* we can't seamlessly recheck the username due to the
             * challenge-response nature of the protocol.
             * Just free the temporary auth_user after merging as
             * much of it new state into the existing one as possible */
            usernamehash->user()->absorb(local_auth_user);
            /* from here on we are working with the original cached credentials. */
            local_auth_user = usernamehash->user();
            auth_user_request->user(local_auth_user);
        } else {
            /* store user in hash's */
            local_auth_user->addToNameCache();
        }
        /* set these to now because this is either a new login from an
         * existing user or a new user */
        local_auth_user->expiretime = current_time.tv_sec;
        auth_user_request->user()->credentials(Auth::Ok);
        debugs(29, 4, HERE << "Successfully validated user via Negotiate. Username '" << blob << "'");

    } else if (strncasecmp(reply, "NA ", 3) == 0 && arg != NULL) {
        /* authentication failure (wrong password, etc.) */

        if (arg) {
            *arg = '\0';
            ++arg;
        }

        auth_user_request->denyMessage(arg);
        auth_user_request->user()->credentials(Auth::Failed);
        safe_free(lm_request->server_blob);
        lm_request->server_blob = xstrdup(blob);
        lm_request->releaseAuthServer();
        debugs(29, 4, HERE << "Failed validating user via Negotiate. Error returned '" << blob << "'");
    } else if (strncasecmp(reply, "BH ", 3) == 0) {
        /* TODO kick off a refresh process. This can occur after a YR or after
         * a KK. If after a YR release the helper and resubmit the request via
         * Authenticate Negotiate start.
         * If after a KK deny the user's request w/ 407 and mark the helper as
         * Needing YR. */
        auth_user_request->denyMessage(blob);
        auth_user_request->user()->credentials(Auth::Failed);
        safe_free(lm_request->server_blob);
        lm_request->releaseAuthServer();
        debugs(29, DBG_IMPORTANT, "ERROR: Negotiate Authentication validating user. Error returned '" << reply << "'");
    } else {
        /* protocol error */
        fatalf("authenticateNegotiateHandleReply: *** Unsupported helper response ***, '%s'\n", reply);
    }

    if (lm_request->request) {
        HTTPMSGUNLOCK(lm_request->request);
        lm_request->request = NULL;
    }
    r->handler(r->data);
    delete r;
}

void
Auth::Negotiate::UserRequest::addAuthenticationInfoHeader(HttpReply * rep, int accel)
{
    http_hdr_type type;

    if (!server_blob)
        return;

    /* don't add to authentication error pages */
    if ((!accel && rep->sline.status == HTTP_PROXY_AUTHENTICATION_REQUIRED)
            || (accel && rep->sline.status == HTTP_UNAUTHORIZED))
        return;

    type = accel ? HDR_AUTHENTICATION_INFO : HDR_PROXY_AUTHENTICATION_INFO;
    httpHeaderPutStrf(&rep->header, type, "Negotiate %s", server_blob);

    safe_free(server_blob);
}
