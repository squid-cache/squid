/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/UserData.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "globals.h"
#include "sbuf/Algorithms.h"
#include "util.h"

const Acl::ParameterFlags &
ACLUserData::supportedFlags() const
{
    static const Acl::ParameterFlags flagNames = { "-i", "+i" };
    return flagNames;
}

bool
ACLUserData::match(char const *user)
{
    debugs(28, 7, "user is " << user << ", case_insensitive is " << flags.case_insensitive);

    if (user == NULL || strcmp(user, "-") == 0)
        return 0;

    if (flags.required) {
        debugs(28, 7, "aclMatchUser: user REQUIRED and auth-info present.");
        return 1;
    }

    bool result = (userDataNames.find(SBuf(user)) != userDataNames.end());
    debugs(28, 7, "returning " << result);
    return result;
}

SBufList
ACLUserData::dump() const
{
    SBufList sl;

    if (flags.required) {
        sl.push_back(SBuf("REQUIRED"));
        return sl;
    }

    if (flags.case_insensitive)
        sl.push_back(SBuf("-i"));

    sl.insert(sl.end(), userDataNames.begin(), userDataNames.end());

    debugs(28,5, "ACLUserData dump output: " <<
           JoinContainerToSBuf(userDataNames.begin(), userDataNames.end(),
                               SBuf(" ")));
    return sl;
}

static bool
CaseSensitiveSBufCompare(const SBuf &lhs, const SBuf &rhs)
{
    return (lhs.cmp(rhs) < 0);
}

static bool
CaseInsensitveSBufCompare(const SBuf &lhs, const SBuf &rhs)
{
    return (lhs.caseCmp(rhs) < 0);
}

ACLUserData::ACLUserData() :
    userDataNames(CaseSensitiveSBufCompare)
{
    flags.case_insensitive = false;
    flags.required = false;
}

void
ACLUserData::parse()
{
    debugs(28, 2, "parsing user list");

    char *t = NULL;
    if ((t = ConfigParser::strtokFile())) {
        SBuf s(t);
        debugs(28, 5, "first token is " << s);

        if (s.cmp("-i",2) == 0) {
            debugs(28, 5, "Going case-insensitive");
            flags.case_insensitive = true;
            // due to how the std::set API work, if we want to change
            // the comparison function we have to create a new std::set
            UserDataNames_t newUdn(CaseInsensitveSBufCompare);
            newUdn.insert(userDataNames.begin(), userDataNames.end());
            swap(userDataNames,newUdn);
        } else if (s.cmp("REQUIRED") == 0) {
            debugs(28, 5, "REQUIRED-type enabled");
            flags.required = true;
        } else {
            if (flags.case_insensitive)
                s.toLower();

            debugs(28, 6, "Adding user " << s);
            userDataNames.insert(s);
        }
    }

    debugs(28, 3, "Case-insensitive-switch is " << flags.case_insensitive);
    /* we might inherit from a previous declaration */

    debugs(28, 4, "parsing following tokens");

    while ((t = ConfigParser::strtokFile())) {
        SBuf s(t);
        debugs(28, 6, "Got token: " << s);

        if (flags.case_insensitive)
            s.toLower();

        debugs(28, 6, "Adding user " << s);
        userDataNames.insert(s);
    }

    if (flags.required && !userDataNames.empty()) {
        debugs(28, DBG_PARSE_NOTE(1), "WARNING: detected attempt to add usernames to an acl of type REQUIRED");
        userDataNames.clear();
    }

    debugs(28,4, "ACL contains " << userDataNames.size() << " users");
}

bool
ACLUserData::empty() const
{
    debugs(28,6,"required: " << flags.required << ", number of users: " << userDataNames.size());
    if (flags.required)
        return false;
    return userDataNames.empty();
}

ACLData<char const *> *
ACLUserData::clone() const
{
    return new ACLUserData;
}

