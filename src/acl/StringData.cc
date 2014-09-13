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
#include "acl/StringData.h"
#include "cache_cf.h"
#include "Debug.h"

ACLStringData::ACLStringData() : values (NULL)
{}

ACLStringData::ACLStringData(ACLStringData const &old) : values (NULL)
{
    assert (!old.values);
}

template<class T>
inline void
xRefFree(T &thing)
{
    xfree (thing);
}

ACLStringData::~ACLStringData()
{
    if (values)
        values->destroy(xRefFree);
}

static int
splaystrcmp (char * const &l, char * const &r)
{
    return strcmp (l,r);
}

void
ACLStringData::insert(const char *value)
{
    values = values->insert(xstrdup(value), splaystrcmp);
}

bool
ACLStringData::match(char const *toFind)
{
    if (!values || !toFind)
        return 0;

    debugs(28, 3, "aclMatchStringList: checking '" << toFind << "'");

    values = values->splay((char *)toFind, splaystrcmp);

    debugs(28, 3, "aclMatchStringList: '" << toFind << "' " << (splayLastResult ? "NOT found" : "found"));

    return !splayLastResult;
}

static void
aclDumpStringWalkee(char * const & node_data, void *outlist)
{
    /* outlist is really a SBufList* */
    static_cast<SBufList*>(outlist)->push_back(SBuf(node_data));
}

SBufList
ACLStringData::dump() const
{
    SBufList sl;
    /* damn this is VERY inefficient for long ACL lists... filling
     * a SBufList this way costs Sum(1,N) iterations. For instance
     * a 1000-elements list will be filled in 499500 iterations.
     */
    values->walk(aclDumpStringWalkee, &sl);
    return sl;
}

void
ACLStringData::parse()
{
    char *t;

    while ((t = strtokFile()))
        values = values->insert(xstrdup(t), splaystrcmp);
}

bool
ACLStringData::empty() const
{
    return values->empty();
}

ACLData<char const *> *
ACLStringData::clone() const
{
    /* Splay trees don't clone yet. */
    assert (!values);
    return new ACLStringData(*this);
}
