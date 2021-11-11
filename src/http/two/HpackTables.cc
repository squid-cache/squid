/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "http/two/HpackTables.h"

// RFC 7541 appendix A
std::list<Http::Two::HpackTables::Entry> Http::Two::HpackTables::staticTable = {
        { /*  1 */ SBuf(":authority"), SBuf() },
        { /*  2 */ SBuf(":method"), SBuf("GET") },
        { /*  3 */ SBuf(":method"), SBuf("POST") },
        { /*  4 */ SBuf(":path"), SBuf("/") },
        { /*  5 */ SBuf(":path"), SBuf("/index.html") },
        { /*  6 */ SBuf(":scheme"), SBuf("http") },
        { /*  7 */ SBuf(":scheme"), SBuf("https") },
        { /*  8 */ SBuf(":status"), SBuf("200") },
        { /*  9 */ SBuf(":status"), SBuf("204") },
        { /* 10 */ SBuf(":status"), SBuf("206") },
        { /* 11 */ SBuf(":status"), SBuf("304") },
        { /* 12 */ SBuf(":status"), SBuf("400") },
        { /* 13 */ SBuf(":status"), SBuf("404") },
        { /* 14 */ SBuf(":status"), SBuf("500") },
        { /* 15 */ SBuf("accept-charset"), SBuf() },
        { /* 16 */ SBuf("accept-encoding"), SBuf("gzip, deflate") },
        { /* 17 */ SBuf("accept-language"), SBuf() },
        { /* 18 */ SBuf("accept-ranges"), SBuf() },
        { /* 19 */ SBuf("accept"), SBuf() },
        { /* 20 */ SBuf("access-control-allow-origin"), SBuf() },
        { /* 21 */ SBuf("age"), SBuf() },
        { /* 22 */ SBuf("allow"), SBuf() },
        { /* 23 */ SBuf("authorization"), SBuf() },
        { /* 24 */ SBuf("cache-control"), SBuf() },
        { /* 25 */ SBuf("content-disposition"), SBuf() },
        { /* 26 */ SBuf("content-encoding"), SBuf() },
        { /* 27 */ SBuf("content-language"), SBuf() },
        { /* 28 */ SBuf("content-length"), SBuf() },
        { /* 29 */ SBuf("content-location"), SBuf() },
        { /* 30 */ SBuf("content-range"), SBuf() },
        { /* 31 */ SBuf("content-type"), SBuf() },
        { /* 32 */ SBuf("cookie"), SBuf() },
        { /* 33 */ SBuf("date"), SBuf() },
        { /* 34 */ SBuf("etag"), SBuf() },
        { /* 35 */ SBuf("expect"), SBuf() },
        { /* 36 */ SBuf("expires"), SBuf() },
        { /* 37 */ SBuf("from"), SBuf() },
        { /* 38 */ SBuf("host"), SBuf() },
        { /* 39 */ SBuf("if-match"), SBuf() },
        { /* 40 */ SBuf("if-modified-since"), SBuf() },
        { /* 41 */ SBuf("if-none-match"), SBuf() },
        { /* 42 */ SBuf("if-range"), SBuf() },
        { /* 43 */ SBuf("if-unmodified-since"), SBuf() },
        { /* 44 */ SBuf("last-modified"), SBuf() },
        { /* 45 */ SBuf("link"), SBuf() },
        { /* 46 */ SBuf("location"), SBuf() },
        { /* 47 */ SBuf("max-forwards"), SBuf() },
        { /* 48 */ SBuf("proxy-authenticate"), SBuf() },
        { /* 49 */ SBuf("proxy-authorization"), SBuf() },
        { /* 50 */ SBuf("range"), SBuf() },
        { /* 51 */ SBuf("referer"), SBuf() },
        { /* 52 */ SBuf("refresh"), SBuf() },
        { /* 53 */ SBuf("retry-after"), SBuf() },
        { /* 54 */ SBuf("server"), SBuf() },
        { /* 55 */ SBuf("set-cookie"), SBuf() },
        { /* 56 */ SBuf("strict-transport-security"), SBuf() },
        { /* 57 */ SBuf("transfer-encoding"), SBuf() },
        { /* 58 */ SBuf("user-agent"), SBuf() },
        { /* 59 */ SBuf("vary"), SBuf() },
        { /* 60 */ SBuf("via"), SBuf() },
        { /* 61 */ SBuf("www-authenticate"), SBuf() }
    };

void
Http::Two::HpackTables::add(const SBuf &name, const SBuf &value)
{
    // RFC 7541 section 4.4 - evict unconditionally before adding
    // this may result in an empty table. That is intentional.

    // RFC 7541 section 4.2 - requirs magic number of +32
    const int32_t addSz = name.length() + value.length() +32;
    evict(addSz);

    if (addSz <= static_cast<int32_t>(capacity_)) {
        dynamicTable.emplace_front(name, value);
        dynamicTableDataSz += addSz;
    }
    // otherwise dont add. that is okay.
}

/// lookup and return the entry at a specific position in the table(s)
/// output has the format:  name ':' SP value
SBuf
Http::Two::HpackTables::lookup(uint32_t idx, bool nameOnly) const
{
    // NP: magic number 61 is the number of entries in the static-table.
    static const size_t staticCount = 61;

    SBuf result;
    if (idx == 0)
        ; // invalid idx. nil result

    else if (idx <= staticCount) {
        // index is in the space for static table entries
        auto e = staticTable.begin();
        uint32_t pos = 1;
        while (pos < idx) {
            e++;
            ++pos;
        }
        result.append(e->first);
        if (!nameOnly) {
            result.append(": ", 2);
            result.append(e->second);
        }

    } else {
        const auto dynamicCount = dynamicTable.size() + staticCount;
        // index is in the space for dynamic table entries
        if (idx > staticCount && idx <= dynamicCount) {
            auto e = dynamicTable.begin();
            uint32_t pos = staticCount +1;
            while (pos < idx) {
                ++e;
                ++pos;
            }
            result.append(e->first);
            if (!nameOnly) {
                result.append(": ", 2);
                result.append(e->second);
            }
        }
    }

    return result;
}

void
Http::Two::HpackTables::changeCapacity(size_t newCap)
{
    if (newCap < capacity_) {
        // RFC 7541 section 4.3 - evict on table reduction
        evict(newCap - capacity_ - dynamicTableDataSz);
    }
    capacity_ = newCap;
}

/// evict entries from the dynamic-table until spaceNeeded has been free'd
/// or the table reaches zero entries, whichever occurs first.
void
Http::Two::HpackTables::evict(int32_t spaceNeeded)
{
    while (spaceNeeded > 0 && !dynamicTable.empty()) {
        auto &e = dynamicTable.back();
        // RFC 7541 section 4.1 requires magic number 32
        // which represents the data pointers in class Entry
        const int32_t entrySz = (e.first.length() + e.second.length() + 32);
        spaceNeeded -= entrySz;
        dynamicTableDataSz -= entrySz;
        dynamicTable.pop_back();
    }
}

