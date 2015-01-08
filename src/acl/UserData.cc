/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
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
#include "util.h"

#include <algorithm>

template<class T>
inline void
xRefFree(T &thing)
{
    xfree (thing);
}

ACLUserData::~ACLUserData()
{
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

struct UserDataAclDumpVisitor {
    SBufList contents;
    void operator() (char * const & node_data) {
        contents.push_back(SBuf(node_data));
    }
};

SBufList
ACLUserData::dump() const
{
    SBufList sl;

    if (flags.case_insensitive)
        sl.push_back(SBuf("-i"));

    if (flags.required) {
        sl.push_back(SBuf("REQUIRED"));
    } else {
        sl.insert(sl.end(), userDataNames.begin(), userDataNames.end());
    }
    return sl;
}

static bool
CaseInsensitveSBufCompare(const SBuf &lhs, const SBuf &rhs)
{
    return (lhs.caseCmp(rhs) < 0);
}
void
ACLUserData::parse()
{
    debugs(28, 2, "parsing user list");
    bool emitInvalidConfigWarning = true;

    char *t = NULL;
    if ((t = ConfigParser::strtokFile())) {
        debugs(28, 5, "aclParseUserList: First token is " << t);

        if (strcmp("-i", t) == 0) {
            debugs(28, 5, "Going case-insensitive");
            flags.case_insensitive = true;
            // due to how the std::set API work, if we want to change
            // the comparison function we have to create a new std::set
            UserDataNames_t newUdn(CaseInsensitveSBufCompare);
            newUdn.insert(userDataNames.begin(), userDataNames.end());
            swap(userDataNames,newUdn);
        } else if (strcmp("REQUIRED", t) == 0) {
            debugs(28, 5, "REQUIRED-type enabled");
            flags.required = true;
            // empty already-accumulated values
            userDataNames.clear();
        } else {
            if (flags.case_insensitive)
                Tolower(t);

            if (!flags.required) { // don't add new users if acl is REQUIRED
                if (emitInvalidConfigWarning) {
                    emitInvalidConfigWarning = false;
                    debugs(28, DBG_PARSE_NOTE(2), "detected attempt to add usernames to an acl of type REQUIRED");
                }
                userDataNames.insert(SBuf(t));
            }
        }
    }

    debugs(28, 3, "Case-insensitive-switch is " << flags.case_insensitive);
    /* we might inherit from a previous declaration */

    debugs(28, 4, "parsing user list");

    while ((t = ConfigParser::strtokFile())) {
        debugs(28, 6, "aclParseUserList: Got token: " << t);

        if (flags.case_insensitive)
            Tolower(t);

        if (!flags.required) { // don't add new users if acl is REQUIRED
            if (emitInvalidConfigWarning) {
                emitInvalidConfigWarning = false;
                debugs(28, DBG_PARSE_NOTE(2), "detected attempt to add usernames to an acl of type REQUIRED");
            }
            userDataNames.insert(SBuf(t));
        }
    }
}

bool
ACLUserData::empty() const
{
    return userDataNames.empty() && !flags.required;
}

ACLData<char const *> *
ACLUserData::clone() const
{
    return new ACLUserData;
}

