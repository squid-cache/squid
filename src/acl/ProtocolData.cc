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
#include "acl/ProtocolData.h"
#include "cache_cf.h"
#include "Debug.h"
#include "wordlist.h"

ACLProtocolData::ACLProtocolData() : values (NULL)
{}

ACLProtocolData::ACLProtocolData(ACLProtocolData const &old) : values (NULL)
{
    assert (!old.values);
}

ACLProtocolData::~ACLProtocolData()
{
    if (values)
        delete values;
}

bool
ACLProtocolData::match(AnyP::ProtocolType toFind)
{
    return values->findAndTune (toFind);
}

/* explicit instantiation required for some systems */

/// \cond AUTODOCS_IGNORE
template cbdata_type CbDataList<AnyP::ProtocolType>::CBDATA_CbDataList;
/// \endcond

SBufList
ACLProtocolData::dump() const
{
    SBufList sl;
    CbDataList<AnyP::ProtocolType> *data = values;

    while (data != NULL) {
        sl.push_back(SBuf(AnyP::ProtocolType_str[data->element]));
        data = data->next;
    }

    return sl;
}

void
ACLProtocolData::parse()
{
    CbDataList<AnyP::ProtocolType> **Tail;
    char *t = NULL;

    for (Tail = &values; *Tail; Tail = &((*Tail)->next));
    while ((t = strtokFile())) {
        int p = AnyP::PROTO_NONE;
        for (; p < AnyP::PROTO_UNKNOWN; ++p) {
            if (strcasecmp(t, AnyP::ProtocolType_str[p]) == 0) {
                CbDataList<AnyP::ProtocolType> *q = new CbDataList<AnyP::ProtocolType>(static_cast<AnyP::ProtocolType>(p));
                *(Tail) = q;
                Tail = &q->next;
                break;
            }
        }
        if (p == AnyP::PROTO_UNKNOWN) {
            debugs(28, DBG_IMPORTANT, "WARNING: Ignoring unknown protocol '" << t << "' in the ACL named '" << AclMatchedName << "'");
            // XXX: store the text pattern of this protocol name for live comparisons
        }
    }
}

bool
ACLProtocolData::empty() const
{
    return values == NULL;
}

ACLData<AnyP::ProtocolType> *
ACLProtocolData::clone() const
{
    /* Splay trees don't clone yet. */
    assert (!values);
    return new ACLProtocolData(*this);
}

