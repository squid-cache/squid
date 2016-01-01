/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/IntRange.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "fatal.h"
#include "Parsing.h"

void
ACLIntRange::parse()
{
    while (char *a = ConfigParser::strtokFile()) {
        char *b = strchr(a, '-');
        unsigned short port1, port2;

        if (b) {
            *b = '\0';
            ++b;
        }

        port1 = xatos(a);

        if (b)
            port2 = xatos(b);
        else
            port2 = port1;

        if (port2 >= port1) {
            RangeType temp(port1, port2+1);
            ranges.push_back(temp);
        } else {
            debugs(28, DBG_CRITICAL, "ACLIntRange::parse: Invalid port value");
            self_destruct();
        }
    }
}

bool
ACLIntRange::empty() const
{
    return ranges.empty();
}

bool
ACLIntRange::match(int i)
{
    RangeType const toFind(i, i+1);
    for (std::list<RangeType>::const_iterator iter = ranges.begin(); iter != ranges.end(); ++iter) {
        const RangeType & element = *iter;
        RangeType result = element.intersection(toFind);

        if (result.size())
            return true;
    }

    return false;
}

ACLData<int> *
ACLIntRange::clone() const
{
    if (!ranges.empty())
        fatal("ACLIntRange::clone: attempt to clone used ACL");

    return new ACLIntRange(*this);
}

ACLIntRange::~ACLIntRange()
{}

SBufList
ACLIntRange::dump() const
{
    SBufList sl;
    for (std::list<RangeType>::const_iterator iter = ranges.begin(); iter != ranges.end(); ++iter) {
        SBuf sb;
        const RangeType & element = *iter;

        if (element.size() == 1)
            sb.Printf("%d", element.start);
        else
            sb.Printf("%d-%d", element.start, element.end-1);

        sl.push_back(sb);
    }

    return sl;
}

