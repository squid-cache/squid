#include "config.h"
#include "auth/negotiate/auth_negotiate.h"
#include "auth/negotiate/negotiateUserRequest.h"
#include "auth/User.h"
#include "helper.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "SquidTime.h"

/**
 * Maximum length (buffer size) for token strings.
 */
// AYJ: must match re-definition in helpers/negotiate_auth/kerberos/negotiate_kerb_auth.cc
#define MAX_AUTHTOKEN_LEN   32768

AuthNegotiateUserRequest::AuthNegotiateUserRequest() :
        /*conn(NULL),*/ auth_state(AUTHENTICATE_STATE_NONE)
{
    waiting=0;
    client_blob=0;
    server_blob=0;
    authserver=NULL;
    request=NULL;
}

AuthNegotiateUserRequest::~AuthNegotiateUserRequest()
{
    assert(RefCountCount()==0);
    safe_free(server_blob);
    safe_free(client_blob);

    if (authserver != NULL) {
        debugs(29, 9, HERE << "releasing server '" << authserver << "'");
        helperStatefulReleaseServer(authserver);
        authserver = NULL;
    }
    if (request) {
        HTTPMSGUNLOCK(request);
        request = NULL;
    }
}

const char *
AuthNegotiateUserRequest::connLastHeader()
{
    return NULL;
}

int
AuthNegotiateUserRequest::authenticated() const
{
    if (auth_state == AUTHENTICATE_STATE_DONE) {
        debugs(29, 9, HERE << "user authenticated.");
        return 1;
    }

    debugs(29, 9, HERE << "user not fully authenticated.");
    return 0;
}

/* See AuthUserRequest.cc::authenticateDirection for return values */
int
AuthNegotiateUserRequest::module_direction()
{
    /* null auth_user is checked for by authenticateDirection */

    if (waiting || client_blob)
        return -1; /* need helper response to continue */

    switch (auth_state) {

        /* no progress at all. */

    case AUTHENTICATE_STATE_NONE:
        debugs(29, DBG_CRITICAL, HERE << "called before Negotiate Authenticate for request " << this << "!. Report a bug to the Squid developers!");
        return -2; /* error */

   case AUTHENTICATE_STATE_FAILED:
        return -2; /* error */

    case AUTHENTICATE_STATE_IN_PROGRESS:
        assert(server_blob);
        return 1; /* send to client */

    case AUTHENTICATE_STATE_DONE:
        return 0; /* do nothing */

    case AUTHENTICATE_STATE_INITIAL:
        debugs(29, DBG_IMPORTANT, "WARNING: Negotiate Authentcation in unexpected state AUTHENTICATE_STATE_INITIAL");
        return -2;
    }

    return -2;
}

/* add the [proxy]authorisation header */
void
AuthNegotiateUserRequest::addHeader(HttpReply * rep, int accel)
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

/** send the initial data to a stateful negotiate authenticator module */
void
AuthNegotiateUserRequest::module_start(RH * handler, void *data)
{
    authenticateStateData *r = NULL;
    static char buf[MAX_AUTHTOKEN_LEN];

    assert(data);
    assert(handler);

    assert(user() != NULL);
    assert(user()->auth_type == AUTH_NEGOTIATE);

    debugs(29, 8, HERE << "auth state is '" << auth_state << "'");

    if (negotiateConfig.authenticate == NULL) {
        debugs(29, DBG_CRITICAL, "ERROR: No Negotiate authentication program configured.");
        handler(data, NULL);
        return;
    }

    r = cbdataAlloc(authenticateStateData);
    r->handler = handler;
    r->data = cbdataReference(data);
    r->auth_user_request = this;

    if (auth_state == AUTHENTICATE_STATE_INITIAL) {
        snprintf(buf, MAX_AUTHTOKEN_LEN, "YR %s\n", client_blob); //CHECKME: can ever client_blob be 0 here?
    } else {
        snprintf(buf, MAX_AUTHTOKEN_LEN, "KK %s\n", client_blob);
    }

    waiting = 1;

    safe_free(client_blob);
    helperStatefulSubmit(negotiateauthenticators, buf, AuthNegotiateUserRequest::HandleReply, r, authserver);
}

/**
 * Atomic action: properly release the Negotiate auth helpers which may have been reserved
 * for this request connections use.
 */
void
AuthNegotiateUserRequest::releaseAuthServer()
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
AuthNegotiateUserRequest::onConnectionClose(ConnStateData *conn)
{
    assert(conn != NULL);

    debugs(29, 8, "AuthNegotiateUserRequest::onConnectionClose: closing connection '" << conn << "' (this is '" << this << "')");

    if (conn->auth_user_request == NULL) {
        debugs(29, 8, "AuthNegotiateUserRequest::onConnectionClose: no auth_user_request");
        return;
    }

    releaseAuthServer();

    /* unlock the connection based lock */
    debugs(29, 9, "AuthNegotiateUserRequest::onConnectionClose: Unlocking auth_user from the connection '" << conn << "'.");

    conn->auth_user_request = NULL;
}

void
AuthNegotiateUserRequest::authenticate(HttpRequest * aRequest, ConnStateData * conn, http_hdr_type type)
{
    assert (this);

    /** Check that we are in the client side, where we can generate auth challenges */
    if (conn == NULL) {
        auth_state = AUTHENTICATE_STATE_FAILED;
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
            blob++;

        while (!xisspace(*blob) && *blob)
            blob++;

        while (xisspace(*blob) && *blob)
            blob++;
    }

    switch (auth_state) {

    case AUTHENTICATE_STATE_NONE:
        /* we've received a negotiate request. pass to a helper */
        debugs(29, 9, HERE << "auth state negotiate none. Received blob: '" << proxy_auth << "'");
        auth_state = AUTHENTICATE_STATE_INITIAL;
        safe_free(client_blob);
        client_blob=xstrdup(blob);
        conn->auth_type = AUTH_NEGOTIATE;
        assert(conn->auth_user_request == NULL);
        conn->auth_user_request = this;
        request = aRequest;
        HTTPMSGLOCK(request);
        break;

   case AUTHENTICATE_STATE_INITIAL:
        debugs(29, 1, HERE << "need to ask helper");
        break;


    case AUTHENTICATE_STATE_IN_PROGRESS:
        /* we should have received a blob from the client. Hand it off to
         * some helper */
        safe_free(client_blob);
        client_blob = xstrdup(blob);
        if (request)
            HTTPMSGUNLOCK(request);
        request = aRequest;
        HTTPMSGLOCK(request);
        break;

    case AUTHENTICATE_STATE_DONE:
        fatal("AuthNegotiateUserRequest::authenticate: unexpected auth state DONE! Report a bug to the squid developers.\n");
        break;

    case AUTHENTICATE_STATE_FAILED:
        /* we've failed somewhere in authentication */
        debugs(29, 9, HERE << "auth state negotiate failed. " << proxy_auth);
        break;
   }

    return;
}

void
AuthNegotiateUserRequest::HandleReply(void *data, void *lastserver, char *reply)
{
    authenticateStateData *r = static_cast<authenticateStateData *>(data);

    int valid;
    char *blob, *arg = NULL;

    debugs(29, 8, HERE << "helper: '" << lastserver << "' sent us '" << (reply ? reply : "<NULL>") << "'");
    valid = cbdataReferenceValid(r->data);

    if (!valid) {
        debugs(29, DBG_IMPORTANT, "ERROR: Negotiate Authentication invalid callback data. helper '" << lastserver << "'.");
        cbdataReferenceDone(r->data);
        authenticateStateFree(r);
        return;
   }

    if (!reply) {
        debugs(29, DBG_IMPORTANT, "ERROR: Negotiate Authentication Helper '" << lastserver << "' crashed!.");
        reply = (char *)"BH Internal error";
    }

    AuthUserRequest::Pointer auth_user_request = r->auth_user_request;
    assert(auth_user_request != NULL);

    AuthNegotiateUserRequest *negotiate_request = dynamic_cast<AuthNegotiateUserRequest *>(auth_user_request.getRaw());
    assert(negotiate_request != NULL);

    assert(negotiate_request->waiting);
    negotiate_request->waiting = 0;
    safe_free(negotiate_request->client_blob);

    assert(auth_user_request->user() != NULL);
    assert(auth_user_request->user()->auth_type == AUTH_NEGOTIATE);

    if (negotiate_request->authserver == NULL)
        negotiate_request->authserver = static_cast<helper_stateful_server*>(lastserver);
    else
        assert(negotiate_request->authserver == lastserver);

    /* seperate out the useful data */
    blob = strchr(reply, ' ');

    if (blob) {
        blob++;
        arg = strchr(blob + 1, ' ');
    } else {
        arg = NULL;
    }

    if (strncasecmp(reply, "TT ", 3) == 0) {
        /* we have been given a blob to send to the client */
        if (arg)
            *arg++ = '\0';
        safe_free(negotiate_request->server_blob);
        negotiate_request->request->flags.must_keepalive = 1;
        if (negotiate_request->request->flags.proxy_keepalive) {
            negotiate_request->server_blob = xstrdup(blob);
            negotiate_request->auth_state = AUTHENTICATE_STATE_IN_PROGRESS;
            auth_user_request->denyMessage("Authentication in progress");
            debugs(29, 4, HERE << "Need to challenge the client with a server blob '" << blob << "'");
        } else {
            negotiate_request->auth_state = AUTHENTICATE_STATE_FAILED;
            auth_user_request->denyMessage("NTLM authentication requires a persistent connection");
        }
    } else if (strncasecmp(reply, "AF ", 3) == 0 && arg != NULL) {
        /* we're finished, release the helper */

        if (arg)
            *arg++ = '\0';

        auth_user_request->user()->username(arg);
        auth_user_request->denyMessage("Login successful");
        safe_free(negotiate_request->server_blob);
        negotiate_request->server_blob = xstrdup(blob);
        negotiate_request->releaseAuthServer();
        negotiate_request->auth_state = AUTHENTICATE_STATE_DONE;
        debugs(29, 4, HERE << "Successfully validated user via Negotiate. Username '" << blob << "'");

        /* connection is authenticated */
        debugs(29, 4, HERE << "authenticated user " << auth_user_request->user()->username());
        /* see if this is an existing user with a different proxy_auth
         * string */
        AuthUserHashPointer *usernamehash = static_cast<AuthUserHashPointer *>(hash_lookup(proxy_auth_username_cache, auth_user_request->user()->username()));
        AuthUser::Pointer local_auth_user = negotiate_request->user();
        while (usernamehash && (usernamehash->user()->auth_type != AUTH_NEGOTIATE || strcmp(usernamehash->user()->username(), auth_user_request->user()->username()) != 0))
            usernamehash = static_cast<AuthUserHashPointer *>(usernamehash->next);
        if (usernamehash) {
            /* we can't seamlessly recheck the username due to the
             * challenge-response nature of the protocol.
             * Just free the temporary auth_user after merging as
             * much of it new state into the existing one as possible */
            usernamehash->user()->absorb(local_auth_user);
            local_auth_user = usernamehash->user();
            /* from here on we are working with the original cached credentials. */
            negotiate_request->_auth_user = local_auth_user;
        } else {
            /* store user in hash's */
            local_auth_user->addToNameCache();
        }
        /* set these to now because this is either a new login from an
         * existing user or a new user */
        local_auth_user->expiretime = current_time.tv_sec;
        negotiate_request->releaseAuthServer();
        negotiate_request->auth_state = AUTHENTICATE_STATE_DONE;

    } else if (strncasecmp(reply, "NA ", 3) == 0 && arg != NULL) {
        /* authentication failure (wrong password, etc.) */

        if (arg)
            *arg++ = '\0';

        auth_user_request->denyMessage(arg);
        negotiate_request->auth_state = AUTHENTICATE_STATE_FAILED;
        safe_free(negotiate_request->server_blob);
        negotiate_request->server_blob = xstrdup(blob);
        negotiate_request->releaseAuthServer();
        debugs(29, 4, HERE << "Failed validating user via Negotiate. Error returned '" << blob << "'");
    } else if (strncasecmp(reply, "BH ", 3) == 0) {
        /* TODO kick off a refresh process. This can occur after a YR or after
         * a KK. If after a YR release the helper and resubmit the request via
         * Authenticate Negotiate start.
         * If after a KK deny the user's request w/ 407 and mark the helper as
         * Needing YR. */
        auth_user_request->denyMessage(blob);
        negotiate_request->auth_state = AUTHENTICATE_STATE_FAILED;
        safe_free(negotiate_request->server_blob);
        negotiate_request->releaseAuthServer();
        debugs(29, DBG_IMPORTANT, "ERROR: Negotiate Authentication validating user. Error returned '" << reply << "'");
    } else {
        /* protocol error */
        fatalf("authenticateNegotiateHandleReply: *** Unsupported helper response ***, '%s'\n", reply);
    }

    negotiate_request->request = NULL;
    r->handler(r->data, NULL);
    cbdataReferenceDone(r->data);
    authenticateStateFree(r);
}

