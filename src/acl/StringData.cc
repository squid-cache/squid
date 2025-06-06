/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/StringData.h"
#include "ConfigParser.h"
#include "debug/Stream.h"

void
ACLStringData::insert(const char *value)
{
    stringValues.insert(SBuf(value));
}

bool
ACLStringData::match(const SBuf &tf)
{
    if (stringValues.empty())
        return 0;

    debugs(28, 3, "aclMatchStringList: checking '" << tf << "'");

    bool found = (stringValues.find(tf) != stringValues.end());
    debugs(28, 3, "aclMatchStringList: '" << tf << "' " << (found ? "found" : "NOT found"));

    return found;
}

// XXX: performance regression due to SBuf(char*) data-copies.
bool
ACLStringData::match(char const *toFind)
{
    if (!toFind) {
        // TODO: Check whether we can Assure(toFind) instead.
        debugs(28, 3, "not matching a nil c-string");
        return false;
    }
    return match(SBuf(toFind));
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
    while (const char *t = ConfigParser::strtokFile())
        stringValues.insert(SBuf(t));
}

bool
ACLStringData::empty() const
{
    return stringValues.empty();
}

