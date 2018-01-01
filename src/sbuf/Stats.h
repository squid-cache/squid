/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
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
    ///Dump statistics to an ostream.
    std::ostream& dump(std::ostream &os) const;

    SBufStats& operator +=(const SBufStats&);

public:
    uint64_t alloc = 0; ///<number of calls to SBuf constructors
    uint64_t allocCopy = 0; ///<number of calls to SBuf copy-constructor
    uint64_t allocFromCString = 0; ///<number of copy-allocations from c-strings
    uint64_t assignFast = 0; ///<number of no-copy assignment operations
    uint64_t clear = 0; ///<number of clear operations
    uint64_t append = 0; ///<number of append operations
    uint64_t moves = 0; ///<number of move constructions/assignments
    uint64_t toStream = 0;  ///<number of write operations to ostreams
    uint64_t setChar = 0; ///<number of calls to setAt
    uint64_t getChar = 0; ///<number of calls to at() and operator[]
    uint64_t compareSlow = 0; ///<number of comparison operations requiring data scan
    uint64_t compareFast = 0; ///<number of comparison operations not requiring data scan
    uint64_t copyOut = 0; ///<number of data-copies to other forms of buffers
    uint64_t rawAccess = 0; ///<number of accesses to raw contents
    uint64_t nulTerminate = 0; ///<number of c_str() terminations
    uint64_t chop = 0;  ///<number of chop operations
    uint64_t trim = 0;  ///<number of trim operations
    uint64_t find = 0;  ///<number of find operations
    uint64_t caseChange = 0; ///<number of toUpper and toLower operations
    uint64_t cowFast = 0; ///<number of cow operations not actually requiring a copy
    uint64_t cowSlow = 0; ///<number of cow operations requiring a copy
    uint64_t live = 0;  ///<number of currently-allocated SBuf
};

#endif /* SQUID_SBUF_STATS_H */

