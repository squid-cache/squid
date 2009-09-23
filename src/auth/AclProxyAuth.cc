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
#include "auth/AclProxyAuth.h"
#include "auth/Gadgets.h"
#include "acl/FilledChecklist.h"
#include "acl/UserData.h"
#include "acl/RegexData.h"
#include "client_side.h"
#include "HttpRequest.h"
#include "auth/Acl.h"
#include "auth/User.h"
#include "auth/UserRequest.h"

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

    if ((ti = AuthenticateAcl(checklist)) != 1)
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
        debugs(28, 0, "Can't use proxy auth because no authentication schemes were compiled.");
        return false;
    }

    if (authenticateActiveSchemeCount() == 0) {
        debugs(28, 0, "Can't use proxy auth because no authentication schemes are fully configured.");
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
ProxyAuthLookup::checkForAsync(ACLChecklist *cl)const
{
    ACLFilledChecklist *checklist = Filled(cl);

    checklist->asyncInProgress(true);
    debugs(28, 3, "ACLChecklist::checkForAsync: checking password via authenticator");

    AuthUserRequest *auth_user_request;
    /* make sure someone created auth_user_request for us */
    assert(checklist->auth_user_request != NULL);
    auth_user_request = checklist->auth_user_request;

    int validated = authenticateValidateUser(auth_user_request);
    assert(validated);
    auth_user_request->start(LookupDone, checklist);
}

void
ProxyAuthLookup::LookupDone(void *data, char *result)
{
    ACLFilledChecklist *checklist = Filled(static_cast<ACLChecklist*>(data));

    assert (checklist->asyncState() == ProxyAuthLookup::Instance());

    if (result != NULL)
        fatal("AclLookupProxyAuthDone: Old code floating around somewhere.\nMake clean and if that doesn't work, report a bug to the squid developers.\n");

    if (!authenticateValidateUser(checklist->auth_user_request) || checklist->conn() == NULL) {
        /* credentials could not be checked either way
         * restart the whole process */
        /* OR the connection was closed, there's no way to continue */
        AUTHUSERREQUESTUNLOCK(checklist->auth_user_request, "ProxyAuthLookup");

        if (checklist->conn() != NULL) {
            AUTHUSERREQUESTUNLOCK(checklist->conn()->auth_user_request, "conn via ProxyAuthLookup");	// DPW discomfort
            checklist->conn()->auth_type = AUTH_BROKEN;
        }
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
    debugs(28, 6, "ACLChecklist::checkForAsync: requiring Proxy Auth header.");
    checklist->currentAnswer(ACCESS_REQ_PROXY_AUTH);
    checklist->changeState (ACLChecklist::NullState::Instance());
    checklist->markFinished();
}

ACL *
ACLProxyAuth::clone() const
{
    return new ACLProxyAuth(*this);
}

int
ACLProxyAuth::matchForCache(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = Filled(cl);
    assert (checklist->auth_user_request);
    return data->match(checklist->auth_user_request->username());
}

/* aclMatchProxyAuth can return two exit codes:
 * 0 : Authorisation for this ACL failed. (Did not match)
 * 1 : Authorisation OK. (Matched)
 */
int
ACLProxyAuth::matchProxyAuth(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = Filled(cl);
    checkAuthForCaching(checklist);
    /* check to see if we have matched the user-acl before */
    int result = cacheMatchAcl(&checklist->auth_user_request->user()->
                               proxy_match_cache, checklist);
    AUTHUSERREQUESTUNLOCK(checklist->auth_user_request, "ACLChecklist via ACLProxyAuth");
    return result;
}

void
ACLProxyAuth::checkAuthForCaching(ACLChecklist *checklist)const
{
    /* for completeness */
    /* consistent parameters ? */
    assert(authenticateUserAuthenticated(Filled(checklist)->auth_user_request));
    /* this check completed */
}

