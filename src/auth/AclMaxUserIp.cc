/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "auth/Acl.h"
#include "auth/AclMaxUserIp.h"
#include "auth/UserRequest.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "Parsing.h"
#include "wordlist.h"

ACLMaxUserIP::ACLMaxUserIP(char const *theClass) :
    class_(theClass),
    maximum(0)
{}

ACL *
ACLMaxUserIP::clone() const
{
    return new ACLMaxUserIP(*this);
}

char const *
ACLMaxUserIP::typeString() const
{
    return class_;
}

bool
ACLMaxUserIP::empty() const
{
    return false;
}

bool
ACLMaxUserIP::valid() const
{
    return maximum > 0;
}

const Acl::Options &
ACLMaxUserIP::options()
{
    static const Acl::BooleanOption BeStrict;
    static const Acl::Options MyOptions = { { "-s", &BeStrict } };
    BeStrict.linkWith(&beStrict);
    return MyOptions;
}

void
ACLMaxUserIP::parse()
{
    if (maximum) {
        debugs(28, DBG_IMPORTANT, "Attempting to alter already set User max IP acl");
        return;
    }

    char *t = ConfigParser::strtokFile();

    if (!t)
        return;

    debugs(28, 5, "aclParseUserMaxIP: First token is " << t);

    maximum = xatoi(t);

    debugs(28, 5, "aclParseUserMaxIP: Max IP address's " << maximum);

    return;
}

/*
 * aclMatchUserMaxIP - check for users logging in from multiple IP's
 * 0 : No match
 * 1 : Match
 */
int
ACLMaxUserIP::match(Auth::UserRequest::Pointer auth_user_request, Ip::Address const &src_addr)
{
    /*
     * the logic for flush the ip list when the limit is hit vs keep
     * it sorted in most recent access order and just drop the oldest
     * one off is currently undecided (RBC)
     */

    if (authenticateAuthUserRequestIPCount(auth_user_request) <= maximum)
        return 0;

    debugs(28, DBG_IMPORTANT, "aclMatchUserMaxIP: user '" << auth_user_request->username() << "' tries to use too many IP addresses (max " << maximum << " allowed)!");

    /* this is a match */
    if (beStrict) {
        /*
         * simply deny access - the user name is already associated with
         * the request
         */
        /* remove _this_ ip, as it is the culprit for going over the limit */
        authenticateAuthUserRequestRemoveIp(auth_user_request, src_addr);
        debugs(28, 4, "aclMatchUserMaxIP: Denying access in strict mode");
    } else {
        /*
         * non-strict - remove some/all of the cached entries
         * ie to allow the user to move machines easily
         */
        authenticateAuthUserRequestClearIp(auth_user_request);
        debugs(28, 4, "aclMatchUserMaxIP: Denying access in non-strict mode - flushing the user ip cache");
    }

    return 1;
}

int
ACLMaxUserIP::match(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = Filled(cl);
    auto answer = AuthenticateAcl(checklist);
    int ti;

    // convert to tri-state ACL match 1,0,-1
    switch (answer) {
    case ACCESS_ALLOWED:
        // check for a match
        ti = match(checklist->auth_user_request, checklist->src_addr);
        checklist->auth_user_request = NULL;
        return ti;

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
ACLMaxUserIP::dump() const
{
    SBufList sl;
    if (!maximum)
        return sl;
    SBuf s;
    s.Printf("%d", maximum);
    sl.push_back(s);
    return sl;
}

