/*
 * $Id$
 *
 * DEBUG: section 28    Access Control
 * AUTHOR: Duane Wessels
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "ACLProxyAuth.h"
#include "authenticate.h"
#include "ACLChecklist.h"
#include "ACLUserData.h"
#include "ACLRegexData.h"
#include "client_side.h"
#include "HttpRequest.h"
#include "AuthUser.h"
#include "AuthUserRequest.h"

ACLProxyAuth::~ACLProxyAuth()
{
    delete data;
}

ACLProxyAuth::ACLProxyAuth(ACLData<char const *> *newData, char const *theType) : data (newData), type_(theType) {}

ACLProxyAuth::ACLProxyAuth (ACLProxyAuth const &old) : data (old.data->clone()), type_(old.type_)
{}

ACLProxyAuth &
ACLProxyAuth::operator= (ACLProxyAuth const &rhs)
{
    data = rhs.data->clone();
    type_ = rhs.type_;
    return *this;
}

char const *
ACLProxyAuth::typeString() const
{
    return type_;
}

void
ACLProxyAuth::parse()
{
    data->parse();
}

int
ACLProxyAuth::match(ACLChecklist *checklist)
{
    int ti;

    if ((ti = checklist->authenticated()) != 1)
        return ti;

    ti = matchProxyAuth(checklist);

    return ti;
}

wordlist *
ACLProxyAuth::dump() const
{
    return data->dump();
}

bool
ACLProxyAuth::empty () const
{
    return data->empty();
}

bool
ACLProxyAuth::valid () const
{
    if (authenticateSchemeCount() == 0) {
        debug(28, 0) ("Can't use proxy auth because no authentication schemes were compiled.\n");
        return false;
    }

    if (authenticateActiveSchemeCount() == 0) {
        debug(28, 0) ("Can't use proxy auth because no authentication schemes are fully configured.\n");
        return false;
    }

    return true;
}

ProxyAuthNeeded ProxyAuthNeeded::instance_;

ProxyAuthNeeded *
ProxyAuthNeeded::Instance()
{
    return &instance_;
}

ProxyAuthLookup ProxyAuthLookup::instance_;

ProxyAuthLookup *
ProxyAuthLookup::Instance()
{
    return &instance_;
}

void
ProxyAuthLookup::checkForAsync(ACLChecklist *checklist)const
{
    checklist->asyncInProgress(true);
    debug(28, 3)
    ("ACLChecklist::checkForAsync: checking password via authenticator\n");

    auth_user_request_t *auth_user_request;
    /* make sure someone created auth_user_request for us */
    assert(checklist->auth_user_request != NULL);
    auth_user_request = checklist->auth_user_request;

    assert(authenticateValidateUser(auth_user_request));
    auth_user_request->start(LookupDone, checklist);
}

void
ProxyAuthLookup::LookupDone(void *data, char *result)
{
    ACLChecklist *checklist = (ACLChecklist *)data;
    assert (checklist->asyncState() == ProxyAuthLookup::Instance());

    if (result != NULL)
        fatal("AclLookupProxyAuthDone: Old code floating around somewhere.\nMake clean and if that doesn't work, report a bug to the squid developers.\n");

    if (!authenticateValidateUser(checklist->auth_user_request) || checklist->conn() == NULL) {
        /* credentials could not be checked either way
         * restart the whole process */
        /* OR the connection was closed, there's no way to continue */
        checklist->auth_user_request->unlock();

        if (checklist->conn().getRaw() != NULL) {
            checklist->conn()->auth_user_request = NULL;
            checklist->conn()->auth_type = AUTH_BROKEN;
        }

        checklist->auth_user_request = NULL;
    }

    checklist->asyncInProgress(false);
    checklist->changeState (ACLChecklist::NullState::Instance());
    checklist->check();
}

void
ProxyAuthNeeded::checkForAsync(ACLChecklist *checklist) const
{
    /* Client is required to resend the request with correct authentication
     * credentials. (This may be part of a stateful auth protocol.)
     * The request is denied.
     */
    debug(28, 6) ("ACLChecklist::checkForAsync: requiring Proxy Auth header.\n");
    checklist->currentAnswer(ACCESS_REQ_PROXY_AUTH);
    checklist->changeState (ACLChecklist::NullState::Instance());
    checklist->markFinished();
}

ACL::Prototype ACLProxyAuth::UserRegistryProtoype(&ACLProxyAuth::UserRegistryEntry_, "proxy_auth");
ACLProxyAuth ACLProxyAuth::UserRegistryEntry_(new ACLUserData, "proxy_auth");
ACL::Prototype ACLProxyAuth::RegexRegistryProtoype(&ACLProxyAuth::RegexRegistryEntry_, "proxy_auth_regex" );
ACLProxyAuth ACLProxyAuth::RegexRegistryEntry_(new ACLRegexData, "proxy_auth_regex");

ACL *
ACLProxyAuth::clone() const
{
    return new ACLProxyAuth(*this);
}

int
ACLProxyAuth::matchForCache(ACLChecklist *checklist)
{
    assert (checklist->auth_user_request);
    return data->match(checklist->auth_user_request->username());
}

/* aclMatchProxyAuth can return two exit codes:
 * 0 : Authorisation for this ACL failed. (Did not match)
 * 1 : Authorisation OK. (Matched)
 */
int
ACLProxyAuth::matchProxyAuth(ACLChecklist *checklist)
{
    checkAuthForCaching(checklist);
    /* check to see if we have matched the user-acl before */
    int result = cacheMatchAcl(&checklist->auth_user_request->user()->
                               proxy_match_cache, checklist);
    checklist->auth_user_request = NULL;
    return result;
}

void
ACLProxyAuth::checkAuthForCaching(ACLChecklist *checklist)const
{
    /* for completeness */

    checklist->auth_user_request->lock()

    ;
    /* consistent parameters ? */
    assert(authenticateUserAuthenticated(checklist->auth_user_request));

    /* this check completed */
    checklist->auth_user_request->unlock();
}

