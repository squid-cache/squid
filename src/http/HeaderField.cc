/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "http/HeaderField.h"
#include "HttpHeaderFieldStat.h"
#include "HttpHeaderTools.h"

Http::HeaderField::HeaderField(Http::HdrType anId, const SBuf &aName, const char *aValue)
{
    assert(any_HdrType_enum_value(anId));
    id = anId;

    if (id != Http::HdrType::OTHER)
        name = Http::HeaderLookupTable.lookup(id).name;
    else
        name = aName;

    value = aValue;

    if (id != Http::HdrType::BAD_HDR)
        ++ headerStatsTable[id].aliveCount;

    debugs(55, 9, "Http::HeaderField construct, this=" << this << ", '" << name << " : " << value );
}

Http::HeaderField::~HeaderField()
{
    debugs(55, 9, "Http::HeaderField destruct, this=" << this << ", '" << name << " : " << value );

    if (id != Http::HdrType::BAD_HDR) {
        assert(headerStatsTable[id].aliveCount);
        -- headerStatsTable[id].aliveCount;
        id = Http::HdrType::BAD_HDR;
    }
}

Http::HeaderField *
Http::HeaderField::clone() const
{
    return new Http::HeaderField(id, name, value.termedBuf());
}

void
Http::HeaderField::packInto(Packable * p) const
{
    assert(p);
    p->append(name.rawContent(), name.length());
    p->append(": ", 2);
    p->append(value.rawBuf(), value.size());
    p->append("\r\n", 2);
}
