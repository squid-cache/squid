#include "squid.h"
#include "auth/basic/auth_basic.h"
#include "auth/basic/User.h"
#include "auth/basic/UserRequest.h"
#include "auth/State.h"
#include "charset.h"
#include "Debug.h"
#include "rfc1738.h"
#include "SquidTime.h"

#if !defined(HELPER_INPUT_BUFFER)
#define HELPER_INPUT_BUFFER  8192
#endif

int
Auth::Basic::UserRequest::authenticated() const
{
    Auth::Basic::User const *basic_auth = dynamic_cast<Auth::Basic::User const *>(user().getRaw());

    if (basic_auth && basic_auth->authenticated())
        return 1;

    return 0;
}

/* log a basic user in
 */
void
Auth::Basic::UserRequest::authenticate(HttpRequest * request, ConnStateData * conn, http_hdr_type type)
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

Auth::Direction
Auth::Basic::UserRequest::module_direction()
{
    /* null auth_user is checked for by Auth::UserRequest::direction() */
    if (user()->auth_type != Auth::AUTH_BASIC)
        return Auth::CRED_ERROR;

    switch (user()->credentials()) {

    case Auth::Unchecked:
    case Auth::Pending:
        return Auth::CRED_LOOKUP;

    case Auth::Ok:
        if (user()->expiretime + static_cast<Auth::Basic::Config*>(Auth::Config::Find("basic"))->credentialsTTL <= squid_curtime)
            return Auth::CRED_LOOKUP;
        return Auth::CRED_VALID;

    case Auth::Failed:
        return Auth::CRED_VALID;

    default:
        return Auth::CRED_ERROR;
    }
}

/* send the initial data to a basic authenticator module */
void
Auth::Basic::UserRequest::module_start(AUTHCB * handler, void *data)
{
    assert(user()->auth_type == Auth::AUTH_BASIC);
    Auth::Basic::User *basic_auth = dynamic_cast<Auth::Basic::User *>(user().getRaw());
    assert(basic_auth != NULL);
    debugs(29, 9, HERE << "'" << basic_auth->username() << ":" << basic_auth->passwd << "'");

    if (static_cast<Auth::Basic::Config*>(Auth::Config::Find("basic"))->authenticateProgram == NULL) {
        debugs(29, DBG_CRITICAL, "ERROR: No Basic authentication program configured.");
        handler(data);
        return;
    }

    /* check to see if the auth_user already has a request outstanding */
    if (user()->credentials() == Auth::Pending) {
        /* there is a request with the same credentials already being verified */

        BasicAuthQueueNode *node = static_cast<BasicAuthQueueNode *>(xcalloc(1, sizeof(BasicAuthQueueNode)));
        assert(node);
        node->auth_user_request = this;
        node->handler = handler;
        node->data = cbdataReference(data);

        /* queue this validation request to be infored of the pending lookup results */
        node->next = basic_auth->auth_queue;
        basic_auth->auth_queue = node;
        return;
    }
    // otherwise submit this request to the auth helper(s) for validation

    /* mark this user as having verification in progress */
    user()->credentials(Auth::Pending);
    char buf[HELPER_INPUT_BUFFER];
    static char username[HELPER_INPUT_BUFFER];
    static char pass[HELPER_INPUT_BUFFER];
    if (static_cast<Auth::Basic::Config*>(user()->config)->utf8) {
        latin1_to_utf8(username, sizeof(username), user()->username());
        latin1_to_utf8(pass, sizeof(pass), basic_auth->passwd);
        xstrncpy(username, rfc1738_escape(username), sizeof(username));
        xstrncpy(pass, rfc1738_escape(pass), sizeof(pass));
    } else {
        xstrncpy(username, rfc1738_escape(user()->username()), sizeof(username));
        xstrncpy(pass, rfc1738_escape(basic_auth->passwd), sizeof(pass));
    }
    int sz = snprintf(buf, sizeof(buf), "%s %s\n", username, pass);
    if (sz<=0) {
        debugs(9, DBG_CRITICAL, "ERROR: Basic Authentication Failure. Can not build helper validation request.");
        handler(data);
    } else if (static_cast<size_t>(sz) >= sizeof(buf)) {
        debugs(9, DBG_CRITICAL, "ERROR: Basic Authentication Failure. user:password exceeds " << sizeof(buf) << " bytes.");
        handler(data);
    } else
        helperSubmit(basicauthenticators, buf, Auth::Basic::UserRequest::HandleReply,
                     new Auth::StateData(this, handler, data));
}

void
Auth::Basic::UserRequest::HandleReply(void *data, char *reply)
{
    Auth::StateData *r = static_cast<Auth::StateData *>(data);
    BasicAuthQueueNode *tmpnode;
    char *t = NULL;
    void *cbdata;
    debugs(29, 5, HERE << "{" << (reply ? reply : "<NULL>") << "}");

    if (reply) {
        if ((t = strchr(reply, ' '))) {
            *t = '\0';
            ++t;
        }

        if (*reply == '\0')
            reply = NULL;
    }

    assert(r->auth_user_request != NULL);
    assert(r->auth_user_request->user()->auth_type == Auth::AUTH_BASIC);

    /* this is okay since we only play with the Auth::Basic::User child fields below
     * and dont pass the pointer itself anywhere */
    Auth::Basic::User *basic_auth = dynamic_cast<Auth::Basic::User *>(r->auth_user_request->user().getRaw());

    assert(basic_auth != NULL);

    if (reply && (strncasecmp(reply, "OK", 2) == 0))
        basic_auth->credentials(Auth::Ok);
    else {
        basic_auth->credentials(Auth::Failed);

        if (t && *t)
            r->auth_user_request->setDenyMessage(t);
    }

    basic_auth->expiretime = squid_curtime;

    if (cbdataReferenceValidDone(r->data, &cbdata))
        r->handler(cbdata);

    cbdataReferenceDone(r->data);

    while (basic_auth->auth_queue) {
        tmpnode = basic_auth->auth_queue->next;

        if (cbdataReferenceValidDone(basic_auth->auth_queue->data, &cbdata))
            basic_auth->auth_queue->handler(cbdata);

        xfree(basic_auth->auth_queue);

        basic_auth->auth_queue = tmpnode;
    }

    delete r;
}
