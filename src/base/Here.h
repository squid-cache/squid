/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_HERE_H
#define SQUID_BASE_HERE_H

#include <iosfwd>

/// source code location of the caller
#define Here() SourceLocation(__FUNCTION__, __FILE__, __LINE__)

/// semi-uniquely identifies a source code location; stable across Squid runs
typedef uint32_t SourceLocationId;

/// returns a hash of a file name
typedef SourceLocationId FileNameHasher(const char *fileName);

/// a caching proxy for `hasher` results
typedef SourceLocationId FileNameHashCacher(const char *fileName, FileNameHasher hasher);

static FileNameHashCacher UnitFileNameHashCacher;

/// a source code location that is cheap to create, copy, and store
class SourceLocation
{
public:
    SourceLocation(const char *aContext, const char *aFileName, const int aLineNo):
        context(aContext),
        fileName(aFileName),
        lineNo(aLineNo),
        fileNameHashCacher(&UnitFileNameHashCacher)
    {}

    /// \returns our location identifier
    SourceLocationId id() const;

    /// describes location using a compact but human-friendly format
    std::ostream &print(std::ostream &os) const;

    const char *context; ///< line-independent location description
    const char *fileName; ///< source file name, often relative to build path
    int lineNo; ///< line number inside the source file name (if positive)

private:
    SourceLocationId calculateId(FileNameHasher) const;
    FileNameHashCacher *fileNameHashCacher;
};

inline std::ostream &
operator <<(std::ostream &os, const SourceLocation &location)
{
    return location.print(os);
}

/// SourceLocation::id() speed optimization hack: Caches `hasher` results. The
/// cache capacity is one filename hash. Each translation unit gets one cache.
static SourceLocationId
UnitFileNameHashCacher(const char *fileName, FileNameHasher hasher)
{
    static SourceLocationId cachedHash = 0;
    static const char *hashedFilename = 0;
    // Each file #included in a translation unit has its own __FILE__ value.
    // Keep the cache fresh (and the result correct).
    if (hashedFilename != fileName) { // cheap pointer comparison
        hashedFilename = fileName;
        cachedHash = hasher(fileName);
    }
    return cachedHash;
}

#endif

