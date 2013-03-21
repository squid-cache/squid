/*
 * DEBUG: section 29    Negotiate Authenticator
 * AUTHOR: Robert Collins, Henrik Nordstrom, Francesco Chemolli
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

/* The functions in this file handle authentication.
 * They DO NOT perform access control or auditing.
 * See acl.c for access control and client_side.c for auditing */

#include "squid.h"
#include "auth/negotiate/auth_negotiate.h"
#include "auth/Gadgets.h"
#include "auth/State.h"
#include "cache_cf.h"
#include "mgr/Registration.h"
#include "Store.h"
#include "client_side.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "SquidTime.h"
#include "auth/negotiate/Scheme.h"
#include "auth/negotiate/User.h"
#include "auth/negotiate/UserRequest.h"
#include "wordlist.h"

/**
 \defgroup AuthNegotiateInternal Negotiate Authenticator Internals
 \ingroup AuthNegotiateAPI
 */

/* Negotiate Scheme */
static AUTHSSTATS authenticateNegotiateStats;

/// \ingroup AuthNegotiateInternal
statefulhelper *negotiateauthenticators = NULL;

/// \ingroup AuthNegotiateInternal
static int authnegotiate_initialised = 0;

/// \ingroup AuthNegotiateInternal
static hash_table *proxy_auth_cache = NULL;

/*
 *
 * Private Functions
 *
 */

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

void
Auth::Negotiate::Config::dump(StoreEntry * entry, const char *name, Auth::Config * scheme)
{
    wordlist *list = authenticateProgram;
    storeAppendPrintf(entry, "%s %s", name, "negotiate");

    while (list != NULL) {
        storeAppendPrintf(entry, " %s", list->key);
        list = list->next;
    }

    storeAppendPrintf(entry, "\n%s negotiate children %d startup=%d idle=%d concurrency=%d\n",
                      name, authenticateChildren.n_max, authenticateChildren.n_startup, authenticateChildren.n_idle, authenticateChildren.concurrency);
    storeAppendPrintf(entry, "%s %s keep_alive %s\n", name, "negotiate", keep_alive ? "on" : "off");

}

Auth::Negotiate::Config::Config() : keep_alive(1)
{ }

void
Auth::Negotiate::Config::parse(Auth::Config * scheme, int n_configured, char *param_str)
{
    if (strcmp(param_str, "program") == 0) {
        if (authenticateProgram)
            wordlistDestroy(&authenticateProgram);

        parse_wordlist(&authenticateProgram);

        requirePathnameExists("auth_param negotiate program", authenticateProgram->key);
    } else if (strcmp(param_str, "children") == 0) {
        authenticateChildren.parseConfig();
    } else if (strcmp(param_str, "keep_alive") == 0) {
        parse_onoff(&keep_alive);
    } else {
        debugs(29, DBG_CRITICAL, "ERROR: unrecognised Negotiate auth scheme parameter '" << param_str << "'");
    }
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
Auth::Negotiate::Config::init(Auth::Config * scheme)
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

/* Negotiate Scheme */

void
Auth::Negotiate::Config::fixHeader(Auth::UserRequest::Pointer auth_user_request, HttpReply *rep, http_hdr_type reqType, HttpRequest * request)
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
    helperStatefulStats(sentry, negotiateauthenticators, "Negotiate Authenticator Statistics");
}

/*
 * Decode a Negotiate [Proxy-]Auth string, placing the results in the passed
 * Auth_user structure.
 */
Auth::UserRequest::Pointer
Auth::Negotiate::Config::decode(char const *proxy_auth)
{
    Auth::Negotiate::User *newUser = new Auth::Negotiate::User(Auth::Config::Find("negotiate"));
    Auth::UserRequest *auth_user_request = new Auth::Negotiate::UserRequest();
    assert(auth_user_request->user() == NULL);

    auth_user_request->user(newUser);
    auth_user_request->user()->auth_type = Auth::AUTH_NEGOTIATE;

    /* all we have to do is identify that it's Negotiate - the helper does the rest */
    debugs(29, 9, HERE << "decode Negotiate authentication");
    return auth_user_request;
}
