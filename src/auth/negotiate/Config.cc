/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 29    Negotiate Authenticator */

/* The functions in this file handle authentication.
 * They DO NOT perform access control or auditing.
 * See acl.c for access control and client_side.c for auditing */

#include "squid.h"
#include "auth/Gadgets.h"
#include "auth/negotiate/Config.h"
#include "auth/negotiate/Scheme.h"
#include "auth/negotiate/User.h"
#include "auth/negotiate/UserRequest.h"
#include "auth/State.h"
#include "cache_cf.h"
#include "client_side.h"
#include "helper.h"
#include "http/Stream.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "mgr/Registration.h"
#include "SquidTime.h"
#include "Store.h"
#include "wordlist.h"

static AUTHSSTATS authenticateNegotiateStats;

statefulhelper *negotiateauthenticators = NULL;

static int authnegotiate_initialised = 0;

static hash_table *proxy_auth_cache = NULL;

void
Auth::Negotiate::Config::rotateHelpers()
{
    /* schedule closure of existing helpers */
    if (negotiateauthenticators) {
        helperStatefulShutdown(negotiateauthenticators);
    }

    /* NP: dynamic helper restart will ensure they start up again as needed. */
}

void
Auth::Negotiate::Config::done()
{
    Auth::SchemeConfig::done();

    authnegotiate_initialised = 0;

    if (negotiateauthenticators) {
        helperStatefulShutdown(negotiateauthenticators);
    }

    if (!shutting_down)
        return;

    delete negotiateauthenticators;
    negotiateauthenticators = NULL;

    if (authenticateProgram)
        wordlistDestroy(&authenticateProgram);

    debugs(29, DBG_IMPORTANT, "Reconfigure: Negotiate authentication configuration cleared.");
}

const char *
Auth::Negotiate::Config::type() const
{
    return Auth::Negotiate::Scheme::GetInstance()->type();
}

/**
 * Initialize helpers and the like for this auth scheme.
 * Called AFTER parsing the config file
 */
void
Auth::Negotiate::Config::init(Auth::SchemeConfig *)
{
    if (authenticateProgram) {

        authnegotiate_initialised = 1;

        if (negotiateauthenticators == NULL)
            negotiateauthenticators = new statefulhelper("negotiateauthenticator");

        if (!proxy_auth_cache)
            proxy_auth_cache = hash_create((HASHCMP *) strcmp, 7921, hash_string);

        assert(proxy_auth_cache);

        negotiateauthenticators->cmdline = authenticateProgram;

        negotiateauthenticators->childs.updateLimits(authenticateChildren);

        negotiateauthenticators->ipc_type = IPC_STREAM;

        helperStatefulOpenServers(negotiateauthenticators);
    }
}

void
Auth::Negotiate::Config::registerWithCacheManager(void)
{
    Mgr::RegisterAction("negotiateauthenticator",
                        "Negotiate User Authenticator Stats",
                        authenticateNegotiateStats, 0, 1);
}

bool
Auth::Negotiate::Config::active() const
{
    return authnegotiate_initialised == 1;
}

bool
Auth::Negotiate::Config::configured() const
{
    if (authenticateProgram && (authenticateChildren.n_max != 0)) {
        debugs(29, 9, HERE << "returning configured");
        return true;
    }

    debugs(29, 9, HERE << "returning unconfigured");
    return false;
}

void
Auth::Negotiate::Config::fixHeader(Auth::UserRequest::Pointer auth_user_request, HttpReply *rep, Http::HdrType reqType, HttpRequest * request)
{
    if (!authenticateProgram)
        return;

    /* Need keep-alive */
    if (!request->flags.proxyKeepalive && request->flags.mustKeepalive)
        return;

    /* New request, no user details */
    if (auth_user_request == NULL) {
        debugs(29, 9, HERE << "Sending type:" << reqType << " header: 'Negotiate'");
        httpHeaderPutStrf(&rep->header, reqType, "Negotiate");

        if (!keep_alive) {
            /* drop the connection */
            rep->header.delByName("keep-alive");
            request->flags.proxyKeepalive = false;
        }
    } else {
        Auth::Negotiate::UserRequest *negotiate_request = dynamic_cast<Auth::Negotiate::UserRequest *>(auth_user_request.getRaw());
        assert(negotiate_request != NULL);

        switch (negotiate_request->user()->credentials()) {

        case Auth::Failed:
            /* here it makes sense to drop the connection, as auth is
             * tied to it, even if MAYBE the client could handle it - Kinkie */
            rep->header.delByName("keep-alive");
            request->flags.proxyKeepalive = false;
        /* fall through */

        case Auth::Ok:
            /* Special case: authentication finished OK but disallowed by ACL.
             * Need to start over to give the client another chance.
             */
            if (negotiate_request->server_blob) {
                debugs(29, 9, HERE << "Sending type:" << reqType << " header: 'Negotiate " << negotiate_request->server_blob << "'");
                httpHeaderPutStrf(&rep->header, reqType, "Negotiate %s", negotiate_request->server_blob);
                safe_free(negotiate_request->server_blob);
            } else {
                debugs(29, 9, HERE << "Connection authenticated");
                httpHeaderPutStrf(&rep->header, reqType, "Negotiate");
            }
            break;

        case Auth::Unchecked:
            /* semantic change: do not drop the connection.
             * 2.5 implementation used to keep it open - Kinkie */
            debugs(29, 9, HERE << "Sending type:" << reqType << " header: 'Negotiate'");
            httpHeaderPutStrf(&rep->header, reqType, "Negotiate");
            break;

        case Auth::Handshake:
            /* we're waiting for a response from the client. Pass it the blob */
            debugs(29, 9, HERE << "Sending type:" << reqType << " header: 'Negotiate " << negotiate_request->server_blob << "'");
            httpHeaderPutStrf(&rep->header, reqType, "Negotiate %s", negotiate_request->server_blob);
            safe_free(negotiate_request->server_blob);
            break;

        default:
            debugs(29, DBG_CRITICAL, "ERROR: Negotiate auth fixHeader: state " << negotiate_request->user()->credentials() << ".");
            fatal("unexpected state in AuthenticateNegotiateFixErrorHeader.\n");
        }
    }
}

static void
authenticateNegotiateStats(StoreEntry * sentry)
{
    if (negotiateauthenticators)
        negotiateauthenticators->packStatsInto(sentry, "Negotiate Authenticator Statistics");
}

/*
 * Decode a Negotiate [Proxy-]Auth string, placing the results in the passed
 * Auth_user structure.
 */
Auth::UserRequest::Pointer
Auth::Negotiate::Config::decode(char const *proxy_auth, const HttpRequest *, const char *aRequestRealm)
{
    Auth::Negotiate::User *newUser = new Auth::Negotiate::User(Auth::SchemeConfig::Find("negotiate"), aRequestRealm);
    Auth::UserRequest *auth_user_request = new Auth::Negotiate::UserRequest();
    assert(auth_user_request->user() == NULL);

    auth_user_request->user(newUser);
    auth_user_request->user()->auth_type = Auth::AUTH_NEGOTIATE;

    auth_user_request->user()->BuildUserKey(proxy_auth, aRequestRealm);

    /* all we have to do is identify that it's Negotiate - the helper does the rest */
    debugs(29, 9, HERE << "decode Negotiate authentication");
    return auth_user_request;
}

