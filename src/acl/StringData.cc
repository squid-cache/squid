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
    values->insert(xstrdup(value), splaystrcmp);
}

bool
ACLStringData::match(char const *toFind)
{
    if (!values || !toFind)
        return 0;

    debugs(28, 3, "aclMatchStringList: checking '" << toFind << "'");

    char * const * result = values->find(const_cast<char *>(toFind), splaystrcmp);

    debugs(28, 3, "aclMatchStringList: '" << toFind << "' " << (result ? "found" : "NOT found"));

    return (result != NULL);
}

// visitor functor to collect the contents of the Arp Acl
struct StringDataAclDumpVisitor {
    SBufList contents;
    void operator() (char * const& node_data) {
        contents.push_back(SBuf(node_data));
    }
};

SBufList
ACLStringData::dump() const
{
    StringDataAclDumpVisitor visitor;
    values->visit(visitor);
    return visitor.contents;
}

void
ACLStringData::parse()
{
    char *t;

    while ((t = strtokFile()))
        values->insert(xstrdup(t), splaystrcmp);
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

