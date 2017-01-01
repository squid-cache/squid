/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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

ACLStringData::ACLStringData(ACLStringData const &old) : stringValues(old.stringValues)
{
}

void
ACLStringData::insert(const char *value)
{
    stringValues.insert(SBuf(value));
}

bool
ACLStringData::match(char const *toFind)
{
    if (stringValues.empty() || !toFind)
        return 0;

    SBuf tf(toFind);
    debugs(28, 3, "aclMatchStringList: checking '" << tf << "'");

    bool found = (stringValues.find(tf) != stringValues.end());
    debugs(28, 3, "aclMatchStringList: '" << tf << "' " << (found ? "found" : "NOT found"));

    return found;
}

SBufList
ACLStringData::dump() const
{
    SBufList sl;
    sl.insert(sl.end(), stringValues.begin(), stringValues.end());
    return sl;
}

void
ACLStringData::parse()
{
    char *t;
    while ((t = strtokFile()))
        stringValues.insert(SBuf(t));
}

bool
ACLStringData::empty() const
{
    return stringValues.empty();
}

ACLData<char const *> *
ACLStringData::clone() const
{
    /* Splay trees don't clone yet. */
    return new ACLStringData(*this);
}

