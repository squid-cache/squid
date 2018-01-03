/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
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
    cowFast += ss.cowFast;
    cowSlow += ss.cowSlow;
    live += ss.live;

    return *this;
}

std::ostream &
SBufStats::dump(std::ostream& os) const
{
    MemBlobStats ststats = MemBlob::GetStats();
    os <<
       "SBuf stats:\nnumber of allocations: " << alloc <<
       "\ncopy-allocations: " << allocCopy <<
       "\ncopy-allocations from C String: " << allocFromCString <<
       "\nlive references: " << live <<
       "\nno-copy assignments: " << assignFast <<
       "\nclearing operations: " << clear <<
       "\nappend operations: " << append <<
       "\nmove operations: " << moves <<
       "\ndump-to-ostream: " << toStream <<
       "\nset-char: " << setChar <<
       "\nget-char: " << getChar <<
       "\ncomparisons with data-scan: " << compareSlow <<
       "\ncomparisons not requiring data-scan: " << compareFast <<
       "\ncopy-out ops: " << copyOut <<
       "\nraw access to memory: " << rawAccess <<
       "\nNULL terminate C string: " << nulTerminate <<
       "\nchop operations: " << chop <<
       "\ntrim operations: " << trim <<
       "\nfind: " << find <<
       "\ncase-change ops: " << caseChange <<
       "\nCOW not actually requiring a copy: " << cowFast <<
       "\nCOW: " << cowSlow <<
       "\naverage store share factor: " <<
       (ststats.live != 0 ? static_cast<float>(live)/ststats.live : 0) <<
       std::endl;
    return os;
}

