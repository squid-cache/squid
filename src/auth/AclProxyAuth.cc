/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/RegexData.h"
#include "acl/UserData.h"
#include "auth/Acl.h"
#include "auth/AclProxyAuth.h"
#include "auth/Gadgets.h"
#include "auth/User.h"
#include "auth/UserRequest.h"
#include "client_side.h"
#include "http/Stream.h"
#include "HttpRequest.h"

ACLProxyAuth::~ACLProxyAuth()
{
    delete data;
}

ACLProxyAuth::ACLProxyAuth(ACLData<char const *> *newData, char const *theType) :
    data(newData),
    type_(theType)
{}

ACLProxyAuth::ACLProxyAuth(ACLProxyAuth const &old) :
    data(old.data->clone()),
    type_(old.type_)
{}

ACLProxyAuth &
ACLProxyAuth::operator=(ACLProxyAuth const &rhs)
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
ACLProxyAuth::parseFlags()
{
    ParseFlags(Acl::NoOptions(), data->supportedFlags());
}

void
ACLProxyAuth::parse()
{
    data->parse();
}

int
ACLProxyAuth::match(ACLChecklist *checklist)
{
    auto answer = AuthenticateAcl(checklist);

    // convert to tri-state ACL match 1,0,-1
    switch (answer) {
    case ACCESS_ALLOWED:
        // check for a match
        return matchProxyAuth(checklist);

    case ACCESS_DENIED:
        return 0; // non-match

    case ACCESS_DUNNO:
    case ACCESS_AUTH_REQUIRED:
    default:
        // If the answer is not allowed or denied (matches/not matches) and
        // async authentication is not in progress, then we are done.
        if (checklist->keepMatching())
            checklist->markFinished(answer, "AuthenticateAcl exception");
        return -1; // other
    }
}

SBufList
ACLProxyAuth::dump() const
{
    return data->dump();
}

bool
ACLProxyAuth::empty() const
{
    return data->empty();
}

bool
ACLProxyAuth::valid() const
{
    if (authenticateSchemeCount() == 0) {
        debugs(28, DBG_CRITICAL, "Can't use proxy auth because no authentication schemes were compiled.");
        return false;
    }

    if (authenticateActiveSchemeCount() == 0) {
        debugs(28, DBG_CRITICAL, "Can't use proxy auth because no authentication schemes are fully configured.");
        return false;
    }

    return true;
}

ProxyAuthLookup ProxyAuthLookup::instance_;

ProxyAuthLookup *
ProxyAuthLookup::Instance()
{
    return &instance_;
}

void
ProxyAuthLookup::checkForAsync(ACLChecklist *cl) const
{
    ACLFilledChecklist *checklist = Filled(cl);

    debugs(28, 3, HERE << "checking password via authenticator");

    /* make sure someone created auth_user_request for us */
    assert(checklist->auth_user_request != NULL);
    assert(checklist->auth_user_request->valid());
    checklist->auth_user_request->start(checklist->request, checklist->al, LookupDone, checklist);
}

void
ProxyAuthLookup::LookupDone(void *data)
{
    ACLFilledChecklist *checklist = Filled(static_cast<ACLChecklist*>(data));

    if (checklist->auth_user_request == NULL || !checklist->auth_user_request->valid() || checklist->conn() == NULL) {
        /* credentials could not be checked either way
         * restart the whole process */
        /* OR the connection was closed, there's no way to continue */
        checklist->auth_user_request = NULL;

        if (checklist->conn() != NULL) {
            checklist->conn()->setAuth(NULL, "proxy_auth ACL failure");
        }
    }

    checklist->resumeNonBlockingCheck(ProxyAuthLookup::Instance());
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
    assert (checklist->auth_user_request != NULL);
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
    if (!checklist->request->flags.sslBumped) {
        if (!authenticateUserAuthenticated(checklist->auth_user_request)) {
            return 0;
        }
    }
    /* check to see if we have matched the user-acl before */
    int result = cacheMatchAcl(&checklist->auth_user_request->user()->proxy_match_cache, checklist);
    checklist->auth_user_request = NULL;
    return result;
}

