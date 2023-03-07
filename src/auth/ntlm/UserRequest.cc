/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "auth/CredentialsCache.h"
#include "auth/ntlm/Config.h"
#include "auth/ntlm/User.h"
#include "auth/ntlm/UserRequest.h"
#include "auth/State.h"
#include "cbdata.h"
#include "client_side.h"
#include "fatal.h"
#include "format/Format.h"
#include "globals.h"
#include "helper.h"
#include "helper/Reply.h"
#include "http/Stream.h"
#include "HttpRequest.h"
#include "MemBuf.h"

Auth::Ntlm::UserRequest::UserRequest() :
    server_blob(nullptr),
    client_blob(nullptr),
    waiting(0),
    request(nullptr)
{}

Auth::Ntlm::UserRequest::~UserRequest()
{
    assert(LockCount()==0);
    safe_free(server_blob);
    safe_free(client_blob);

    releaseAuthServer();

    if (request) {
        HTTPMSGUNLOCK(request);
        request = nullptr;
    }
}

const char *
Auth::Ntlm::UserRequest::connLastHeader()
{
    return nullptr;
}

int
Auth::Ntlm::UserRequest::authenticated() const
{
    if (user() != nullptr && user()->credentials() == Auth::Ok) {
        debugs(29, 9, "user authenticated.");
        return 1;
    }

    debugs(29, 9, "user not fully authenticated.");
    return 0;
}

const char *
Auth::Ntlm::UserRequest::credentialsStr()
{
    static char buf[MAX_AUTHTOKEN_LEN];
    int printResult;
    if (user()->credentials() == Auth::Pending) {
        printResult = snprintf(buf, sizeof(buf), "YR %s\n", client_blob);
    } else {
        printResult = snprintf(buf, sizeof(buf), "KK %s\n", client_blob);
    }

    // truncation is OK because we are used only for logging
    if (printResult < 0) {
        debugs(29, 2, "Can not build ntlm authentication credentials.");
        buf[0] = '\0';
    } else if (printResult >= (int)sizeof(buf))
        debugs(29, 2, "Ntlm authentication credentials truncated.");

    return buf;
}

Auth::Direction
Auth::Ntlm::UserRequest::module_direction()
{
    /* null auth_user is checked for by Auth::UserRequest::direction() */

    if (waiting || client_blob)
        return Auth::CRED_LOOKUP; /* need helper response to continue */

    if (user()->auth_type != Auth::AUTH_NTLM)
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
        debugs(29, DBG_IMPORTANT, "WARNING: NTLM Authentication in unexpected state: " << user()->credentials());
        return Auth::CRED_ERROR;
    }
}

void
Auth::Ntlm::UserRequest::startHelperLookup(HttpRequest *, AccessLogEntry::Pointer &al, AUTHCB * handler, void *data)
{
    static char buf[MAX_AUTHTOKEN_LEN];

    assert(data);
    assert(handler);

    if (static_cast<Auth::Ntlm::Config*>(Auth::SchemeConfig::Find("ntlm"))->authenticateProgram == nullptr) {
        debugs(29, DBG_CRITICAL, "ERROR: NTLM Start: no NTLM program configured.");
        handler(data);
        return;
    }

    debugs(29, 8, "credentials state is '" << user()->credentials() << "'");

    const char *keyExtras = helperRequestKeyExtras(request, al);
    int printResult = 0;
    if (user()->credentials() == Auth::Pending) {
        if (keyExtras)
            printResult = snprintf(buf, sizeof(buf), "YR %s %s\n", client_blob, keyExtras);
        else
            printResult = snprintf(buf, sizeof(buf), "YR %s\n", client_blob); //CHECKME: can ever client_blob be 0 here?
    } else {
        if (keyExtras)
            printResult = snprintf(buf, sizeof(buf), "KK %s %s\n", client_blob, keyExtras);
        else
            printResult = snprintf(buf, sizeof(buf), "KK %s\n", client_blob);
    }
    waiting = 1;

    if (printResult < 0 || printResult >= (int)sizeof(buf)) {
        if (printResult < 0)
            debugs(29, DBG_CRITICAL, "ERROR: Can not build ntlm authentication helper request");
        else
            debugs(29, DBG_CRITICAL, "ERROR: Ntlm authentication helper request too big for the " << sizeof(buf) << "-byte buffer.");
        handler(data);
        return;
    }

    safe_free(client_blob);
    helperStatefulSubmit(ntlmauthenticators, buf, Auth::Ntlm::UserRequest::HandleReply,
                         new Auth::StateData(this, handler, data), reservationId);
}

/**
 * Atomic action: properly release the NTLM auth helpers which may have been reserved
 * for this request connections use.
 */
void
Auth::Ntlm::UserRequest::releaseAuthServer()
{
    if (reservationId) {
        debugs(29, 6, reservationId);
        ntlmauthenticators->cancelReservation(reservationId);
        reservationId.clear();
    } else
        debugs(29, 6, "No NTLM auth server to release.");
}

void
Auth::Ntlm::UserRequest::authenticate(HttpRequest * aRequest, ConnStateData * conn, Http::HdrType type)
{
    /* Check that we are in the client side, where we can generate
     * auth challenges */

    if (conn == nullptr || !cbdataReferenceValid(conn)) {
        user()->credentials(Auth::Failed);
        debugs(29, DBG_IMPORTANT, "WARNING: NTLM Authentication attempt to perform authentication without a connection!");
        return;
    }

    if (waiting) {
        debugs(29, DBG_IMPORTANT, "WARNING: NTLM Authentication waiting for helper reply!");
        return;
    }

    if (server_blob) {
        debugs(29, 2, "need to challenge client '" << server_blob << "'!");
        return;
    }

    /* get header */
    const char *proxy_auth = aRequest->header.getStr(type);

    /* locate second word */
    const char *blob = proxy_auth;

    /* if proxy_auth is actually NULL, we'd better not manipulate it. */
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
        /* we've received a ntlm request. pass to a helper */
        debugs(29, 9, "auth state ntlm none. Received blob: '" << proxy_auth << "'");
        user()->credentials(Auth::Pending);
        safe_free(client_blob);
        client_blob=xstrdup(blob);
        assert(conn->getAuth() == nullptr);
        conn->setAuth(this, "new NTLM handshake request");
        request = aRequest;
        HTTPMSGLOCK(request);
        break;

    case Auth::Pending:
        debugs(29, DBG_IMPORTANT, "need to ask helper");
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
        fatal("Auth::Ntlm::UserRequest::authenticate: unexpected auth state DONE! Report a bug to the squid developers.\n");
        break;

    case Auth::Failed:
        /* we've failed somewhere in authentication */
        debugs(29, 9, "auth state ntlm failed. " << proxy_auth);
        break;
    }
}

void
Auth::Ntlm::UserRequest::HandleReply(void *data, const Helper::Reply &reply)
{
    Auth::StateData *r = static_cast<Auth::StateData *>(data);

    debugs(29, 8, reply.reservationId << " got reply=" << reply);

    if (!cbdataReferenceValid(r->data)) {
        debugs(29, DBG_IMPORTANT, "ERROR: NTLM Authentication invalid callback data(" << reply.reservationId <<")");
        delete r;
        return;
    }

    Auth::UserRequest::Pointer auth_user_request = r->auth_user_request;
    assert(auth_user_request != nullptr);

    // add new helper kv-pair notes to the credentials object
    // so that any transaction using those credentials can access them
    static const NotePairs::Names appendables = { SBuf("group"), SBuf("tag") };
    auth_user_request->user()->notes.replaceOrAddOrAppend(&reply.notes, appendables);
    // remove any private credentials detail which got added.
    auth_user_request->user()->notes.remove("token");

    Auth::Ntlm::UserRequest *lm_request = dynamic_cast<Auth::Ntlm::UserRequest *>(auth_user_request.getRaw());
    assert(lm_request != nullptr);
    assert(lm_request->waiting);

    lm_request->waiting = 0;
    safe_free(lm_request->client_blob);

    assert(auth_user_request->user() != nullptr);
    assert(auth_user_request->user()->auth_type == Auth::AUTH_NTLM);

    if (!lm_request->reservationId)
        lm_request->reservationId = reply.reservationId;
    else
        assert(lm_request->reservationId == reply.reservationId);

    switch (reply.result) {
    case Helper::TT:
        /* we have been given a blob to send to the client */
        safe_free(lm_request->server_blob);
        lm_request->request->flags.mustKeepalive = true;
        if (lm_request->request->flags.proxyKeepalive) {
            const char *serverBlob = reply.notes.findFirst("token");
            lm_request->server_blob = xstrdup(serverBlob);
            auth_user_request->user()->credentials(Auth::Handshake);
            auth_user_request->setDenyMessage("Authentication in progress");
            debugs(29, 4, "Need to challenge the client with a server token: '" << serverBlob << "'");
        } else {
            auth_user_request->user()->credentials(Auth::Failed);
            auth_user_request->setDenyMessage("NTLM authentication requires a persistent connection");
        }
        break;

    case Helper::Okay: {
        /* we're finished, release the helper */
        const char *userLabel = reply.notes.findFirst("user");
        if (!userLabel) {
            auth_user_request->user()->credentials(Auth::Failed);
            safe_free(lm_request->server_blob);
            lm_request->releaseAuthServer();
            debugs(29, DBG_CRITICAL, "ERROR: NTLM Authentication helper returned no username. Result: " << reply);
            break;
        }
        auth_user_request->user()->username(userLabel);
        auth_user_request->setDenyMessage("Login successful");
        safe_free(lm_request->server_blob);
        lm_request->releaseAuthServer();

        debugs(29, 4, "Successfully validated user via NTLM. Username '" << userLabel << "'");
        /* connection is authenticated */
        debugs(29, 4, "authenticated user " << auth_user_request->user()->username());
        /* see if this is an existing user */
        auto local_auth_user = lm_request->user();
        auto cached_user = Auth::Ntlm::User::Cache()->lookup(auth_user_request->user()->userKey());
        if (!cached_user) {
            local_auth_user->addToNameCache();
        } else {
            /* we can't seamlessly recheck the username due to the
             * challenge-response nature of the protocol.
             * Just free the temporary auth_user after merging as
             * much of it new state into the existing one as possible */
            cached_user->absorb(local_auth_user);
            /* from here on we are working with the original cached credentials. */
            local_auth_user = cached_user;
            auth_user_request->user(local_auth_user);
        }
        /* set these to now because this is either a new login from an
         * existing user or a new user */
        local_auth_user->expiretime = current_time.tv_sec;
        auth_user_request->user()->credentials(Auth::Ok);
        debugs(29, 4, "Successfully validated user via NTLM. Username '" << auth_user_request->user()->username() << "'");
    }
    break;

    case Helper::Error:
        /* authentication failure (wrong password, etc.) */
        auth_user_request->denyMessageFromHelper("NTLM", reply);
        auth_user_request->user()->credentials(Auth::Failed);
        safe_free(lm_request->server_blob);
        lm_request->releaseAuthServer();
        debugs(29, 4, "Failed validating user via NTLM. Result: " << reply);
        break;

    case Helper::Unknown:
        debugs(29, DBG_IMPORTANT, "ERROR: NTLM Authentication Helper crashed (" << reply.reservationId << ")");
        [[fallthrough]];

    case Helper::TimedOut:
    case Helper::BrokenHelper:
        /* TODO kick off a refresh process. This can occur after a YR or after
         * a KK. If after a YR release the helper and resubmit the request via
         * Authenticate NTLM start.
         * If after a KK deny the user's request w/ 407 and mark the helper as
         * Needing YR. */
        if (reply.result == Helper::Unknown)
            auth_user_request->setDenyMessage("Internal Error");
        else
            auth_user_request->denyMessageFromHelper("NTLM", reply);
        auth_user_request->user()->credentials(Auth::Failed);
        safe_free(lm_request->server_blob);
        lm_request->releaseAuthServer();
        debugs(29, DBG_IMPORTANT, "ERROR: NTLM Authentication validating user. Result: " << reply);
        break;
    }

    if (lm_request->request) {
        HTTPMSGUNLOCK(lm_request->request);
        lm_request->request = nullptr;
    }
    r->handler(r->data);
    delete r;
}

