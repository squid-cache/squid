/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/MethodData.h"
#include "ConfigParser.h"
#include "http/RequestMethod.h"

int ACLMethodData::ThePurgeCount = 0;

ACLMethodData::ACLMethodData(ACLMethodData const &old)
{
    assert(old.values.empty());
}

ACLMethodData::~ACLMethodData()
{
    values.clear();
}

bool
ACLMethodData::match(HttpRequestMethod toFind)
{
    for (auto i = values.begin(); i != values.end(); ++i) {
        if (*i == toFind) {
            // tune the list for LRU ordering
            values.erase(i);
            values.push_front(toFind);
            return true;
        }
    }
    return false;
}

SBufList
ACLMethodData::dump() const
{
    SBufList sl;
    for (std::list<HttpRequestMethod>::const_iterator i = values.begin(); i != values.end(); ++i) {
        sl.push_back((*i).image());
    }

    return sl;
}

void
ACLMethodData::parse()
{
    while (char *t = ConfigParser::strtokFile()) {
        HttpRequestMethod m;
        m.HttpRequestMethodXXX(t);
        values.push_back(m);
        if (values.back() == Http::METHOD_PURGE)
            ++ThePurgeCount; // configuration code wants to know
    }
}

ACLData<HttpRequestMethod> *
ACLMethodData::clone() const
{
    assert(values.empty());
    return new ACLMethodData(*this);
}

