/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "sbuf/MemBlob.h"
#include "sbuf/SBuf.h"
#include "sbuf/Stats.h"

#include <iostream>

SBufStats::SizeRecorder SBufStats::SBufSizeAtDestructRecorder = nullptr;
SBufStats::SizeRecorder SBufStats::MemBlobSizeAtDestructRecorder = nullptr;

void
SBufStats::RecordSBufSizeAtDestruct(const size_t sz)
{
    if (SBufSizeAtDestructRecorder)
        SBufSizeAtDestructRecorder(sz);
}

void
SBufStats::RecordMemBlobSizeAtDestruct(const size_t sz)
{
    if (MemBlobSizeAtDestructRecorder)
        MemBlobSizeAtDestructRecorder(sz);
}

SBufStats&
SBufStats::operator +=(const SBufStats& ss)
{
    alloc += ss.alloc;
    allocCopy += ss.allocCopy;
    allocFromCString += ss.allocFromCString;
    assignFast += ss.assignFast;
    clear += ss.clear;
    append += ss.append;
    moves += ss.moves;
    toStream += ss.toStream;
    setChar += ss.setChar;
    getChar += ss.getChar;
    compareSlow += ss.compareSlow;
    compareFast += ss.compareFast;
    copyOut += ss.copyOut;
    rawAccess += ss.rawAccess;
    nulTerminate += ss.nulTerminate;
    chop += ss.chop;
    trim += ss.trim;
    find += ss.find;
    caseChange += ss.caseChange;
    cowAvoided += ss.cowAvoided;
    cowShift += ss.cowShift;
    cowJustAlloc += ss.cowJustAlloc;
    cowAllocCopy += ss.cowAllocCopy;
    live += ss.live;

    return *this;
}

void
SBufStats::dump(std::ostream& yaml) const
{
    MemBlobStats ststats = MemBlob::GetStats();
    const std::string indent("  ");
    yaml << "SBuf stats:\n" <<
         indent << "allocations: " << alloc << '\n' <<
         indent << "copy-allocations: " << allocCopy << '\n' <<
         indent << "copy-allocations from cstring: " << allocFromCString << '\n' <<
         indent << "live references: " << live << '\n' <<
         indent << "no-copy assignments: " << assignFast << '\n' <<
         indent << "clearing operations: " << clear << '\n' <<
         indent << "append operations: " << append << '\n' <<
         indent << "move operations: " << moves << '\n' <<
         indent << "dump-to-ostream: " << toStream << '\n' <<
         indent << "set-char: " << setChar << '\n' <<
         indent << "get-char: " << getChar << '\n' <<
         indent << "comparisons with data-scan: " << compareSlow << '\n' <<
         indent << "comparisons not requiring data-scan: " << compareFast << '\n' <<
         indent << "copy-out ops: " << copyOut << '\n' <<
         indent << "raw access to memory: " << rawAccess << '\n' <<
         indent << "NULL terminate cstring: " << nulTerminate << '\n' <<
         indent << "chop operations: " << chop << '\n' <<
         indent << "trim operations: " << trim << '\n' <<
         indent << "find: " << find << '\n' <<
         indent << "case-change ops: " << caseChange << '\n' <<
         indent << "COW completely avoided: " << cowAvoided << '\n' <<
         indent << "COW replaced with memmove: " << cowShift << '\n' <<
         indent << "COW requiring an empty buffer allocation: " << cowJustAlloc << '\n' <<
         indent << "COW requiring allocation and copying: " << cowAllocCopy << '\n' <<
         indent << "average store share factor: " << std::fixed << std::setprecision(3) <<
         (ststats.live != 0 ? static_cast<float>(live)/ststats.live : 0) << '\n';
}

