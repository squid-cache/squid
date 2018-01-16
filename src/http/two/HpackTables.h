/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_TWO_HPACKTABLES_H
#define SQUID_SRC_HTTP_TWO_HPACKTABLES_H

#include "sbuf/SBuf.h"

#include <list>

namespace Http
{
namespace Two
{

/**
 * An HPACK context lookup table(s).
 *
 * Governed by RFC 7541 section 2.3, section 4, and Appendix A
 */
class HpackTables
{
public:
    // RFC 7540 section 6.5.2 - default table size 4096 octets
    HpackTables(size_t maxCapacity = 4096) : capacity_(maxCapacity) {}

    /// add an entry to the dynamic table.
    void add(const SBuf &name, const SBuf &value);

    /// Lookup and return the entry at a idx position in the table space.
    /// If nameOnly is set to true, only the header name will be returned,
    /// otherwise a full Name:value line excluding CRLF will be returned.
    SBuf lookup(uint32_t idx, bool nameOnly = false) const;

    /// capacity can be negotiated with the peer
    void changeCapacity(size_t newCap);

private:
    void evict(int32_t spaceNeeded);

    /// size limit on data stored in the dynamic table.
    size_t capacity_;

    // an entry is a pair of SBuf storing name and optional field-value
    typedef std::pair<SBuf, SBuf> Entry;

    /// RFC 7541 section 2.3.1 static table
    /// A static list of Entries ordered in alphabetically
    static std::list<Entry> staticTable;

    /// RFC 7541 section 2.3.2 dynamic table
    /// A list of Entries ordered in FIFO style
    std::list<Entry> dynamicTable;

    size_t dynamicTableDataSz; ///< size of the data stored in dynamicTable
};

} // namespace Two
} // namespace Http

#endif /* SQUID_SRC_HTTP_TWO_HPACKTABLES_H */

