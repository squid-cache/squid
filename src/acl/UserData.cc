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
#include "util.h"

template<class T>
inline void
xRefFree(T &thing)
{
    xfree (thing);
}

ACLUserData::~ACLUserData()
{
    if (names) {
        names->destroy(xRefFree);
        delete names;
    }
}

static int
splaystrcasecmp (char * const &l, char * const &r)
{
    return strcasecmp ((char *)l,(char *)r);
}

static int
splaystrcmp (char * const &l, char * const &r)
{
    return strcmp ((char *)l,(char *)r);
}

bool
ACLUserData::match(char const *user)
{
    debugs(28, 7, "aclMatchUser: user is " << user << ", case_insensitive is " << flags.case_insensitive);

    if (user == NULL || strcmp(user, "-") == 0)
        return 0;

    if (flags.required) {
        debugs(28, 7, "aclMatchUser: user REQUIRED and auth-info present.");
        return 1;
    }

    char * const *result;

    if (flags.case_insensitive)
        result = names->find(const_cast<char *>(user), splaystrcasecmp);
    else
        result = names->find(const_cast<char *>(user), splaystrcmp);

    /* Top=splay_splay(user,Top,(splayNode::SPLAYCMP *)dumping_strcmp); */
    debugs(28, 7, "aclMatchUser: returning " << (result != NULL));

    return (result != NULL);
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

    /* damn this is VERY inefficient for long ACL lists... filling
     * a SBufList this way costs Sum(1,N) iterations. For instance
     * a 1000-elements list will be filled in 499500 iterations.
     */
    if (flags.required) {
        sl.push_back(SBuf("REQUIRED"));
    } else if (names) {
        UserDataAclDumpVisitor visitor;
        names->visit(visitor);
        sl.splice(sl.end(),visitor.contents);
    }

    return sl;
}

void
ACLUserData::parse()
{
    debugs(28, 2, "aclParseUserList: parsing user list");

    if (!names)
        names = new Splay<char *>();

    char *t = NULL;
    if ((t = ConfigParser::strtokFile())) {
        debugs(28, 5, "aclParseUserList: First token is " << t);

        if (strcmp("-i", t) == 0) {
            debugs(28, 5, "aclParseUserList: Going case-insensitive");
            flags.case_insensitive = true;
        } else if (strcmp("REQUIRED", t) == 0) {
            debugs(28, 5, "aclParseUserList: REQUIRED-type enabled");
            flags.required = true;
        } else {
            if (flags.case_insensitive)
                Tolower(t);

            names->insert(xstrdup(t), splaystrcmp);
        }
    }

    debugs(28, 3, "aclParseUserList: Case-insensitive-switch is " << flags.case_insensitive);
    /* we might inherit from a previous declaration */

    debugs(28, 4, "aclParseUserList: parsing user list");

    while ((t = ConfigParser::strtokFile())) {
        debugs(28, 6, "aclParseUserList: Got token: " << t);

        if (flags.case_insensitive)
            Tolower(t);

        names->insert(xstrdup(t), splaystrcmp);
    }
}

bool
ACLUserData::empty() const
{
    return (!names || names->empty()) && !flags.required;
}

ACLData<char const *> *
ACLUserData::clone() const
{
    /* Splay trees don't clone yet. */
    assert (!names);
    return new ACLUserData;
}

