/*
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
#include "acl/Checklist.h"
#include "acl/UserData.h"
#include "ConfigParser.h"
#include "Debug.h"

template<class T>
inline void
xRefFree(T &thing)
{
    xfree (thing);
}

ACLUserData::~ACLUserData()
{
    if (names)
        names->destroy(xRefFree);
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
    SplayNode<char *> *Top = names;

    debugs(28, 7, "aclMatchUser: user is " << user << ", case_insensitive is " << flags.case_insensitive);
    debugs(28, 8, "Top is " << Top << ", Top->data is " << ((char *) (Top != NULL ? (Top)->data : "Unavailable")));

    if (user == NULL || strcmp(user, "-") == 0)
        return 0;

    if (flags.required) {
        debugs(28, 7, "aclMatchUser: user REQUIRED and auth-info present.");
        return 1;
    }

    if (flags.case_insensitive)
        Top = Top->splay((char *)user, splaystrcasecmp);
    else
        Top = Top->splay((char *)user, splaystrcmp);

    /* Top=splay_splay(user,Top,(splayNode::SPLAYCMP *)dumping_strcmp); */
    debugs(28, 7, "aclMatchUser: returning " << !splayLastResult << ",Top is " <<
           Top << ", Top->data is " << ((char *) (Top ? Top->data : "Unavailable")));

    names = Top;

    return !splayLastResult;
}

static void
aclDumpUserListWalkee(char * const & node_data, void *outlist)
{
    /* outlist is really a SBufList* */
    static_cast<SBufList *>(outlist)->push_back(SBuf(node_data));
}

SBufList
ACLUserData::dump()
{
    SBufList sl;

    if (flags.case_insensitive)
        sl.push_back(SBuf("-i"));

    /* damn this is VERY inefficient for long ACL lists... filling
     * a SBufList this way costs Sum(1,N) iterations. For instance
     * a 1000-elements list will be filled in 499500 iterations.
     */
    if (flags.required)
        sl.push_back(SBuf("REQUIRED"));
    else if (names)
        names->walk(aclDumpUserListWalkee, &sl);

    return sl;
}

void
ACLUserData::parse()
{
    debugs(28, 2, "aclParseUserList: parsing user list");
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

            names = names->insert(xstrdup(t), splaystrcmp);
        }
    }

    debugs(28, 3, "aclParseUserList: Case-insensitive-switch is " << flags.case_insensitive);
    /* we might inherit from a previous declaration */

    debugs(28, 4, "aclParseUserList: parsing user list");

    while ((t = ConfigParser::strtokFile())) {
        debugs(28, 6, "aclParseUserList: Got token: " << t);

        if (flags.case_insensitive)
            Tolower(t);

        names = names->insert(xstrdup(t), splaystrcmp);
    }
}

bool
ACLUserData::empty() const
{
    return names->empty() && !flags.required;
}

ACLData<char const *> *
ACLUserData::clone() const
{
    /* Splay trees don't clone yet. */
    assert (!names);
    return new ACLUserData;
}
