/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/basic/Config.h"
#include "auth/basic/User.h"
#include "auth/basic/UserRequest.h"
#include "auth/QueueNode.h"
#include "auth/State.h"
#include "charset.h"
#include "Debug.h"
#include "format/Format.h"
#include "helper.h"
#include "helper/Reply.h"
#include "HttpMsg.h"
#include "HttpRequest.h"
#include "MemBuf.h"
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

const char *
Auth::Basic::UserRequest::credentialsStr()
{
    Auth::Basic::User const *basic_auth = dynamic_cast<Auth::Basic::User const *>(user().getRaw());
    if (basic_auth)
        return basic_auth->passwd;
    return NULL;
}

/* log a basic user in
 */
void
Auth::Basic::UserRequest::authenticate(HttpRequest *, ConnStateData *, Http::HdrType)
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
Auth::Basic::UserRequest::startHelperLookup(HttpRequest *request, AccessLogEntry::Pointer &al, AUTHCB * handler, void *data)
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

        Auth::QueueNode *node = new Auth::QueueNode(this, handler, data);

        /* queue this validation request to be infored of the pending lookup results */
        node->next = basic_auth->queue;
        basic_auth->queue = node;
        return;
    }
    // otherwise submit this request to the auth helper(s) for validation

    /* mark this user as having verification in progress */
    user()->credentials(Auth::Pending);
    char buf[HELPER_INPUT_BUFFER];
    static char usern[HELPER_INPUT_BUFFER];
    static char pass[HELPER_INPUT_BUFFER];
    if (static_cast<Auth::Basic::Config*>(user()->config)->utf8) {
        latin1_to_utf8(usern, sizeof(usern), user()->username());
        latin1_to_utf8(pass, sizeof(pass), basic_auth->passwd);
        xstrncpy(usern, rfc1738_escape(usern), sizeof(usern));
        xstrncpy(pass, rfc1738_escape(pass), sizeof(pass));
    } else {
        xstrncpy(usern, rfc1738_escape(user()->username()), sizeof(usern));
        xstrncpy(pass, rfc1738_escape(basic_auth->passwd), sizeof(pass));
    }
    int sz = 0;
    if (const char *keyExtras = helperRequestKeyExtras(request, al))
        sz = snprintf(buf, sizeof(buf), "%s %s %s\n", usern, pass, keyExtras);
    else
        sz = snprintf(buf, sizeof(buf), "%s %s\n", usern, pass);

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
Auth::Basic::UserRequest::HandleReply(void *data, const Helper::Reply &reply)
{
    Auth::StateData *r = static_cast<Auth::StateData *>(data);
    void *cbdata;
    debugs(29, 5, HERE << "reply=" << reply);

    assert(r->auth_user_request != NULL);
    assert(r->auth_user_request->user()->auth_type == Auth::AUTH_BASIC);

    // add new helper kv-pair notes to the credentials object
    // so that any transaction using those credentials can access them
    r->auth_user_request->user()->notes.appendNewOnly(&reply.notes);

    /* this is okay since we only play with the Auth::Basic::User child fields below
     * and do not pass the pointer itself anywhere */
    Auth::Basic::User *basic_auth = dynamic_cast<Auth::Basic::User *>(r->auth_user_request->user().getRaw());

    assert(basic_auth != NULL);

    if (reply.result == Helper::Okay)
        basic_auth->credentials(Auth::Ok);
    else {
        basic_auth->credentials(Auth::Failed);

        if (reply.other().hasContent())
            r->auth_user_request->setDenyMessage(reply.other().content());
    }

    basic_auth->expiretime = squid_curtime;

    if (cbdataReferenceValidDone(r->data, &cbdata))
        r->handler(cbdata);

    cbdataReferenceDone(r->data);

    while (basic_auth->queue) {
        if (cbdataReferenceValidDone(basic_auth->queue->data, &cbdata))
            basic_auth->queue->handler(cbdata);

        Auth::QueueNode *tmpnode = basic_auth->queue->next;
        basic_auth->queue->next = NULL;
        delete basic_auth->queue;

        basic_auth->queue = tmpnode;
    }

    delete r;
}

