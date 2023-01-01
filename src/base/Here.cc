/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Here.h"

#include <iostream>

/* File name hashing helpers */

// Build prefix is the file system path leading to Squid src/ source directory.
// It is "." for in-tree builds but may be lengthy and sensitive otherwise.

/// \returns the build prefix length or, if estimation is not possible, zero
static size_t
BuildPrefixLength()
{
    // The hard-coded tail must be kept in sync with this file actual name!
    const char *tail = "src/base/Here.cc";
    const char *full = __FILE__;

    // Disable heuristic if it does not work.
    if (strstr(full, tail) == 0)
        return 0;

    return strlen(full) - strlen(tail);
}

/// \returns filename portion without the build prefix
static const char *
SkipBuildPrefix(const char* path)
{
    static const size_t ToSkip = BuildPrefixLength();
    return path + ToSkip;
}

/// quickly computes a (weak) hash of a file name
static SourceLocationId
FileNameHash(const char *path)
{
    // Keep in sync with FileNameHash() in scripts/calc-must-ids.pl!

    const char *name = strrchr(path, '/');
    if (name)
        ++name; // skip '/'
    else
        name = path;

    uint32_t hash = 0;
    uint32_t iterations = 0;
    while (*name) {
        ++iterations;
        hash ^= 271 * static_cast<uint32_t>(*name);
        ++name;
    }
    return hash ^ (iterations * 271);
}

/* SourceLocation */

SourceLocationId
SourceLocation::id() const
{
    const auto fnameHashFull = fileNameHashCacher(fileName, &FileNameHash);
    // 32 bits = 18 bits for the filename hash + 14 bits for the line number.
    // Keep in sync with ComputeMustIds() in scripts/calc-must-ids.pl.
    const auto fnameHash = fnameHashFull % 0x3FFFF;
    return (fnameHash << 14) | (lineNo & 0x3FFF);
}

std::ostream &
SourceLocation::print(std::ostream &os) const
{
    if (fileName) {
        os << SkipBuildPrefix(fileName);

        // TODO: Use more common and search-friendlier fileName:lineNo: format.
        if (lineNo > 0)
            os << '(' << lineNo << ')';
    }
    if (context) {
        if (fileName)
            os << ' ';
        os << context;
    }
    return os;
}

