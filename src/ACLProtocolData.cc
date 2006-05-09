/*
 * $Id: ACLProtocolData.cc,v 1.8 2006/05/08 23:38:33 robertc Exp $
 *
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
#include "ACLProtocolData.h"
#include "ACLChecklist.h"
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
ACLProtocolData::match(protocol_t toFind)
{
    return values->findAndTune (toFind);
}

/* explicit instantiation required for some systems */

template cbdata_type List<protocol_t>
::CBDATA_List;

wordlist *
ACLProtocolData::dump()
{
    wordlist *W = NULL;
    List<protocol_t> *data = values;

    while (data != NULL) {
        wordlistAdd(&W, ProtocolStr[data->element]);
        data = data->next;
    }

    return W;
}

void
ACLProtocolData::parse()
{
    List<protocol_t> **Tail;
    char *t = NULL;

    for (Tail = &values; *Tail; Tail = &((*Tail)->next))

        ;
    while ((t = strtokFile())) {
        List<protocol_t> *q = new List<protocol_t> (urlParseProtocol(t));
        *(Tail) = q;
        Tail = &q->next;
    }
}

bool
ACLProtocolData::empty() const
{
    return values == NULL;
}

ACLData<protocol_t> *
ACLProtocolData::clone() const
{
    /* Splay trees don't clone yet. */
    assert (!values);
    return new ACLProtocolData(*this);
}
