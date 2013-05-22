/*
 * DEBUG: section 29    NTLM Authenticator
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
#include "auth/Gadgets.h"
#include "auth/ntlm/auth_ntlm.h"
#include "auth/ntlm/Scheme.h"
#include "auth/ntlm/User.h"
#include "auth/ntlm/UserRequest.h"
#include "auth/State.h"
#include "cache_cf.h"
#include "mgr/Registration.h"
#include "Store.h"
#include "client_side.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "wordlist.h"
#include "SquidTime.h"

/* NTLM Scheme */
static AUTHSSTATS authenticateNTLMStats;

statefulhelper *ntlmauthenticators = NULL;
static int authntlm_initialised = 0;

static hash_table *proxy_auth_cache = NULL;

/*
 *
 * Private Functions
 *
 */

void
Auth::Ntlm::Config::rotateHelpers()
{
    /* schedule closure of existing helpers */
    if (ntlmauthenticators) {
        helperStatefulShutdown(ntlmauthenticators);
    }

    /* NP: dynamic helper restart will ensure they start up again as needed. */
}

/* free any allocated configuration details */
void
Auth::Ntlm::Config::done()
{
    authntlm_initialised = 0;

    if (ntlmauthenticators) {
        helperStatefulShutdown(ntlmauthenticators);
    }

    if (!shutting_down)
        return;

    delete ntlmauthenticators;
    ntlmauthenticators = NULL;

    if (authenticateProgram)
        wordlistDestroy(&authenticateProgram);

    debugs(29, DBG_IMPORTANT, "Reconfigure: NTLM authentication configuration cleared.");
}

void
Auth::Ntlm::Config::dump(StoreEntry * entry, const char *name, Auth::Config * scheme)
{
    wordlist *list = authenticateProgram;
    storeAppendPrintf(entry, "%s %s", name, "ntlm");

    while (list != NULL) {
        storeAppendPrintf(entry, " %s", list->key);
        list = list->next;
    }

    storeAppendPrintf(entry, "\n%s ntlm children %d startup=%d idle=%d concurrency=%d\n",
                      name, authenticateChildren.n_max, authenticateChildren.n_startup, authenticateChildren.n_idle, authenticateChildren.concurrency);
    storeAppendPrintf(entry, "%s %s keep_alive %s\n", name, "ntlm", keep_alive ? "on" : "off");

}

Auth::Ntlm::Config::Config() : keep_alive(1)
{ }

void
Auth::Ntlm::Config::parse(Auth::Config * scheme, int n_configured, char *param_str)
{
    if (strcmp(param_str, "program") == 0) {
        if (authenticateProgram)
            wordlistDestroy(&authenticateProgram);

        parse_wordlist(&authenticateProgram);

        requirePathnameExists("auth_param ntlm program", authenticateProgram->key);
    } else if (strcmp(param_str, "children") == 0) {
        authenticateChildren.parseConfig();
    } else if (strcmp(param_str, "keep_alive") == 0) {
        parse_onoff(&keep_alive);
    } else {
        debugs(29, DBG_CRITICAL, "ERROR unrecognised NTLM auth scheme parameter '" << param_str << "'");
    }
}

const char *
Auth::Ntlm::Config::type() const
{
    return Auth::Ntlm::Scheme::GetInstance()->type();
}

/* Initialize helpers and the like for this auth scheme. Called AFTER parsing the
 * config file */
void
Auth::Ntlm::Config::init(Auth::Config * scheme)
{
    if (authenticateProgram) {

        authntlm_initialised = 1;

        if (ntlmauthenticators == NULL)
            ntlmauthenticators = new statefulhelper("ntlmauthenticator");

        if (!proxy_auth_cache)
            proxy_auth_cache = hash_create((HASHCMP *) strcmp, 7921, hash_string);

        assert(proxy_auth_cache);

        ntlmauthenticators->cmdline = authenticateProgram;

        ntlmauthenticators->childs.updateLimits(authenticateChildren);

        ntlmauthenticators->ipc_type = IPC_STREAM;

        helperStatefulOpenServers(ntlmauthenticators);
    }
}

void
Auth::Ntlm::Config::registerWithCacheManager(void)
{
    Mgr::RegisterAction("ntlmauthenticator",
                        "NTLM User Authenticator Stats",
                        authenticateNTLMStats, 0, 1);
}

bool
Auth::Ntlm::Config::active() const
{
    return authntlm_initialised == 1;
}

bool
Auth::Ntlm::Config::configured() const
{
    if ((authenticateProgram != NULL) && (authenticateChildren.n_max != 0)) {
        debugs(29, 9, HERE << "returning configured");
        return true;
    }

    debugs(29, 9, HERE << "returning unconfigured");
    return false;
}

/* NTLM Scheme */

void
Auth::Ntlm::Config::fixHeader(Auth::UserRequest::Pointer auth_user_request, HttpReply *rep, http_hdr_type hdrType, HttpRequest * request)
{
    if (!authenticateProgram)
        return;

    /* Need keep-alive */
    if (!request->flags.proxyKeepalive && request->flags.mustKeepalive)
        return;

    /* New request, no user details */
    if (auth_user_request == NULL) {
        debugs(29, 9, HERE << "Sending type:" << hdrType << " header: 'NTLM'");
        httpHeaderPutStrf(&rep->header, hdrType, "NTLM");

        if (!keep_alive) {
            /* drop the connection */
            request->flags.proxyKeepalive = false;
        }
    } else {
        Auth::Ntlm::UserRequest *ntlm_request = dynamic_cast<Auth::Ntlm::UserRequest *>(auth_user_request.getRaw());
        assert(ntlm_request != NULL);

        switch (ntlm_request->user()->credentials()) {

        case Auth::Failed:
            /* here it makes sense to drop the connection, as auth is
             * tied to it, even if MAYBE the client could handle it - Kinkie */
            request->flags.proxyKeepalive = false;
            /* fall through */

        case Auth::Ok:
            /* Special case: authentication finished OK but disallowed by ACL.
             * Need to start over to give the client another chance.
             */
            /* fall through */

        case Auth::Unchecked:
            /* semantic change: do not drop the connection.
             * 2.5 implementation used to keep it open - Kinkie */
            debugs(29, 9, HERE << "Sending type:" << hdrType << " header: 'NTLM'");
            httpHeaderPutStrf(&rep->header, hdrType, "NTLM");
            break;

        case Auth::Handshake:
            /* we're waiting for a response from the client. Pass it the blob */
            debugs(29, 9, HERE << "Sending type:" << hdrType << " header: 'NTLM " << ntlm_request->server_blob << "'");
            httpHeaderPutStrf(&rep->header, hdrType, "NTLM %s", ntlm_request->server_blob);
            safe_free(ntlm_request->server_blob);
            break;

        default:
            debugs(29, DBG_CRITICAL, "NTLM Auth fixHeader: state " << ntlm_request->user()->credentials() << ".");
            fatal("unexpected state in AuthenticateNTLMFixErrorHeader.\n");
        }
    }
}

static void
authenticateNTLMStats(StoreEntry * sentry)
{
    helperStatefulStats(sentry, ntlmauthenticators, "NTLM Authenticator Statistics");
}

/*
 * Decode a NTLM [Proxy-]Auth string, placing the results in the passed
 * Auth_user structure.
 */
Auth::UserRequest::Pointer
Auth::Ntlm::Config::decode(char const *proxy_auth)
{
    Auth::Ntlm::User *newUser = new Auth::Ntlm::User(Auth::Config::Find("ntlm"));
    Auth::UserRequest::Pointer auth_user_request = new Auth::Ntlm::UserRequest();
    assert(auth_user_request->user() == NULL);

    auth_user_request->user(newUser);
    auth_user_request->user()->auth_type = Auth::AUTH_NTLM;

    /* all we have to do is identify that it's NTLM - the helper does the rest */
    debugs(29, 9, HERE << "decode: NTLM authentication");
    return auth_user_request;
}
