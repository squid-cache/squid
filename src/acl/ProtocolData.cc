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
#include "acl/ProtocolData.h"
#include "acl/Checklist.h"
#include "cache_cf.h"
#include "Debug.h"
#include "URLScheme.h"
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

/// \cond AUTODOCS-IGNORE
template cbdata_type CbDataList<AnyP::ProtocolType>::CBDATA_CbDataList;
/// \endcond

wordlist *
ACLProtocolData::dump()
{
    wordlist *W = NULL;
    CbDataList<AnyP::ProtocolType> *data = values;

    while (data != NULL) {
        wordlistAdd(&W, AnyP::ProtocolType_str[data->element]);
        data = data->next;
    }

    return W;
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
