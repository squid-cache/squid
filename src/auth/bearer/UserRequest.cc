/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/bearer/Config.h"
#include "auth/bearer/User.h"
#include "auth/bearer/UserRequest.h"
#include "auth/QueueNode.h"
#include "auth/State.h"
#include "fatal.h"
#include "helper.h"

int
Auth::Bearer::UserRequest::authenticated() const
{
    if (user() && user()->credentials() == Auth::Ok) {
        debugs(29, 9, "user authenticated");
        return 1;
    }

    debugs(29, 9, "user not fully authenticated");
    return 0;
}

const char *
Auth::Bearer::UserRequest::credentialsStr()
{
    static char buf[MAX_AUTHTOKEN_LEN];
    buf[0] = '\0';

    if (const auto *usr = dynamic_cast<const Bearer::User*>(user().getRaw()))
        snprintf(buf, sizeof(buf), SQUIDSBUFPH "\n", SQUIDSBUFPRINT(usr->token->b68encoded));
    return buf;
}

Auth::Direction
Auth::Bearer::UserRequest::module_direction()
{
    // null auth_user is checked for by Auth::UserRequest::direction()

    if (user()->auth_type != Auth::AUTH_BEARER)
        return Auth::CRED_ERROR;

    switch (user()->credentials()) {

    case Auth::Unchecked:
    case Auth::Pending:
        return Auth::CRED_LOOKUP;

    case Auth::Ok:
        if (user()->ttl() <= 0)
            return Auth::CRED_LOOKUP;
        return Auth::CRED_VALID;

    case Auth::Failed:
        return Auth::CRED_VALID;

    default:
        debugs(29, DBG_IMPORTANT, "WARNING: Bearer Authentication in unexpected state: " << user()->credentials());
        return Auth::CRED_ERROR;
    }
}

void
Auth::Bearer::UserRequest::startHelperLookup(HttpRequest *req, AccessLogEntry::Pointer &al, AUTHCB *handler, void *data)
{
    assert(data);
    assert(handler);

    if (!SchemeConfig::Find("bearer")->authenticateProgram) {
        debugs(29, DBG_CRITICAL, "ERROR: No Bearer authentication program configured.");
        handler(data);
        return;
    }

    assert(user());
    assert(user()->auth_type == Auth::AUTH_BEARER);

    auto *bearer_auth = dynamic_cast<Bearer::User *>(user().getRaw());
    assert(bearer_auth);

    // check to see if the user already has a request outstanding
    if (user()->credentials() == Auth::Pending) {

        debugs(29, 8, "token " << bearer_auth->token->b68encoded << " queue after lookup already underway");
        // there is a request with the same credentials already being verified
        auto *node = new Auth::QueueNode(this, handler, data);

        // queue this validation request to be informed of the pending lookup results
        node->next = bearer_auth->queue;
        bearer_auth->queue = node;
        return;
    }
    // otherwise submit this request to the auth helper(s) for validation

    debugs(29, 8, "credentials state is " << user()->credentials());

    static char buf[MAX_AUTHTOKEN_LEN];
    int sz;
    if (const auto *keyExtras = helperRequestKeyExtras(req, al))
        sz = snprintf(buf, sizeof(buf), SQUIDSBUFPH " %s\n", SQUIDSBUFPRINT(bearer_auth->token->b68encoded), keyExtras);
    else
        sz = snprintf(buf, sizeof(buf), SQUIDSBUFPH "\n", SQUIDSBUFPRINT(bearer_auth->token->b68encoded));

    if (sz<=0) {
        debugs(9, DBG_CRITICAL, "ERROR: Bearer Authentication Failure. Can not build helper validation request.");
        handler(data);
    } else if (static_cast<size_t>(sz) >= sizeof(buf)) {
        debugs(9, DBG_CRITICAL, "ERROR: Bearer Authentication Failure. Helper request line exceeds " << sizeof(buf) << " bytes.");
        handler(data);
    } else {
        user()->credentials(Auth::Pending);
        debugs(29, 3, "token " << bearer_auth->token->b68encoded << " lookup started");
        helperSubmit(bearerauthenticators, buf, Bearer::UserRequest::HandleReply,
                     new Auth::StateData(this, handler, data));
    }
}

void
Auth::Bearer::UserRequest::authenticate(HttpRequest *, ConnStateData *, Http::HdrType)
{
    assert(user());

    // if the password is not ok, do an identity
    if (!user() || user()->credentials() != Auth::Ok)
        return;

    // are we about to recheck the credentials externally?
    if (user()->ttl() <= 0) {
        debugs(29, 4, "credentials expired - rechecking");
        user()->credentials(Auth::Unchecked);
        return;
    }

    // we have been through the external helper, and the credentials haven't expired
    debugs(29, 9, "user " << user()->username() << " authenticated");
}

void
Auth::Bearer::UserRequest::HandleReply(void *data, const Helper::Reply &reply)
{
    auto *r = static_cast<Auth::StateData *>(data);

    debugs(29, 8, reply.reservationId << " got reply=" << reply);

    if (!cbdataReferenceValid(r->data)) {
        debugs(29, DBG_IMPORTANT, "ERROR: Bearer Authentication invalid callback data.");
        delete r;
        return;
    }

    auto auth_user_request = r->auth_user_request;
    assert(auth_user_request);

    // add new helper kv-pair notes to the credentials object
    // so that any transaction using those credentials can access them
    auth_user_request->user()->notes.appendNewOnly(&reply.notes);

    assert(auth_user_request->user());
    assert(auth_user_request->user()->auth_type == Auth::AUTH_BEARER);

    switch (reply.result) {
    case Helper::Okay: {
        const auto *userNote = reply.notes.findFirst("user");
        if (!userNote) {
            /* protocol error */
            fatalf("Auth::Bearer::HandleReply: *** Unsupported helper response ***, '%s'\n", reply.other().content());
            break;
        }

        auto *usr = dynamic_cast<Bearer::User *>(auth_user_request->user().getRaw());
        /* we're finished, user is authenticated */
        usr->username(userNote);
        auth_user_request->denyMessage("Login successful");

        const auto *ttlNote = reply.notes.findFirst("ttl");
        const int64_t ttl = (ttlNote ? strtoll(ttlNote, nullptr, 10) : -1);
        usr->token->expires = current_time.tv_sec + ttl;
        usr->expiretime = max(usr->expiretime, usr->token->expires);
        usr->credentials(Auth::Ok);
        usr->addToNameCache();
        debugs(29, 4, "Successfully validated user via Bearer. Username " << auth_user_request->user()->username());
    }
    break;

    case Helper::Error: {
        /* authentication failure (wrong password, etc.) */
        if (const auto *messageNote = reply.notes.findFirst("message"))
            auth_user_request->denyMessage(messageNote);
        else
            auth_user_request->denyMessage("Bearer Authentication denied with no reason given");

        auto *usr = dynamic_cast<Bearer::User *>(auth_user_request->user().getRaw());

        const auto *ttlNote = reply.notes.findFirst("ttl");
        const int64_t ttl = (ttlNote ? strtoll(ttlNote, nullptr, 10) : -1);
        usr->token->expires = current_time.tv_sec + ttl;
        usr->expiretime = max(usr->expiretime, usr->token->expires);
        usr->credentials(Auth::Failed);
        debugs(29, 4, "Failed validating user via Bearer. Result: " << reply);
    }
    break;

    case Helper::Unknown:
    case Helper::TimedOut:
    case Helper::TT:
    case Helper::BrokenHelper:
        if (const auto *errNote = reply.notes.findFirst("message"))
            auth_user_request->denyMessage(errNote);
        else
            auth_user_request->denyMessage("Bearer Authentication failed with no reason given");
        auth_user_request->user()->credentials(Auth::Failed);
        debugs(29, DBG_IMPORTANT, "ERROR: Bearer Authentication validating user. Result: " << reply);
    break;
    }

    // Notify all waiting transactions of the result
    void *cbdata;
    if (cbdataReferenceValidDone(r->data, &cbdata))
        r->handler(cbdata);

    cbdataReferenceDone(r->data);

    auto *local_usr = dynamic_cast<Bearer::User *>(auth_user_request->user().getRaw());
    while (local_usr->queue) {
        if (cbdataReferenceValidDone(local_usr->queue->data, &cbdata))
            local_usr->queue->handler(cbdata);

        auto *tmpnode = local_usr->queue->next;
        local_usr->queue->next = nullptr;
        delete local_usr->queue;

        local_usr->queue = tmpnode;
    }

    delete r;
}
