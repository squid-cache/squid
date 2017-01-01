/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SBUF_STATS_H
#define SQUID_SBUF_STATS_H

#include <iosfwd>

/**
 * Container for various SBuf class-wide statistics.
 *
 * The stats are not completely accurate; they're mostly meant to
 * understand whether Squid is leaking resources
 * and whether SBuf is paying off the expected gains.
 */
class SBufStats
{
public:
    uint64_t alloc; ///<number of calls to SBuf constructors
    uint64_t allocCopy; ///<number of calls to SBuf copy-constructor
    uint64_t allocFromCString; ///<number of copy-allocations from c-strings
    uint64_t assignFast; ///<number of no-copy assignment operations
    uint64_t clear; ///<number of clear operations
    uint64_t append; ///<number of append operations
    uint64_t moves; ///<number of move constructions/assignments
    uint64_t toStream;  ///<number of write operations to ostreams
    uint64_t setChar; ///<number of calls to setAt
    uint64_t getChar; ///<number of calls to at() and operator[]
    uint64_t compareSlow; ///<number of comparison operations requiring data scan
    uint64_t compareFast; ///<number of comparison operations not requiring data scan
    uint64_t copyOut; ///<number of data-copies to other forms of buffers
    uint64_t rawAccess; ///<number of accesses to raw contents
    uint64_t nulTerminate; ///<number of c_str() terminations
    uint64_t chop;  ///<number of chop operations
    uint64_t trim;  ///<number of trim operations
    uint64_t find;  ///<number of find operations
    uint64_t caseChange; ///<number of toUpper and toLower operations
    uint64_t cowFast; ///<number of cow operations not actually requiring a copy
    uint64_t cowSlow; ///<number of cow operations requiring a copy
    uint64_t live;  ///<number of currently-allocated SBuf

    ///Dump statistics to an ostream.
    std::ostream& dump(std::ostream &os) const;
    SBufStats();

    SBufStats& operator +=(const SBufStats&);
};

#endif /* SQUID_SBUF_STATS_H */

