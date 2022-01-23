/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/ProtocolData.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "wordlist.h"

ACLProtocolData::ACLProtocolData(ACLProtocolData const &old)
{
    assert(old.values.empty());
}

ACLProtocolData::~ACLProtocolData()
{
    values.clear();
}

bool
ACLProtocolData::match(AnyP::ProtocolType toFind)
{
    for (auto itr = values.begin(); itr != values.end(); ++itr) {
        if (*itr == toFind) {
            // tune the list for LRU ordering
            values.erase(itr);
            values.push_front(toFind);
            return true;
        }
    }
    return false;
}

SBufList
ACLProtocolData::dump() const
{
    SBufList sl;
    for (std::list<AnyP::ProtocolType>::const_iterator itr = values.begin(); itr != values.end(); ++itr) {
        sl.push_back(SBuf(AnyP::ProtocolType_str[*itr]));
    }

    return sl;
}

void
ACLProtocolData::parse()
{
    while (char *t = ConfigParser::strtokFile()) {
        int p = AnyP::PROTO_NONE;
        for (; p < AnyP::PROTO_UNKNOWN; ++p) {
            if (strcasecmp(t, AnyP::ProtocolType_str[p]) == 0) {
                values.push_back(static_cast<AnyP::ProtocolType>(p));
                break;
            }
        }
        if (p == AnyP::PROTO_UNKNOWN) {
            debugs(28, DBG_IMPORTANT, "WARNING: Ignoring unknown protocol '" << t << "' in the ACL named '" << AclMatchedName << "'");
            // XXX: store the text pattern of this protocol name for live comparisons
        }
    }
}

ACLData<AnyP::ProtocolType> *
ACLProtocolData::clone() const
{
    /* Splay trees don't clone yet. */
    assert(values.empty());
    return new ACLProtocolData(*this);
}

