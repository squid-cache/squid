/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_MEM_SEGMENT_H
#define SQUID_IPC_MEM_SEGMENT_H

#include "base/RunnersRegistry.h"
#include "sbuf/forward.h"
#include "SquidString.h"

namespace Ipc
{

namespace Mem
{

/// POSIX shared memory segment
class Segment
{
public:
    /// Create a shared memory segment.
    Segment(const char *const id);
    ~Segment();

    /// Whether shared memory support is available
    static bool Enabled();

    /// Create a new shared memory segment. Unlinks the segment on destruction.
    void create(const off_t aSize);
    void open(); ///< Open an existing shared memory segment.

    const String &name() { return theName; } ///< shared memory segment name
    off_t size() { return theSize; } ///< shared memory segment size
    void *mem() { return reserve(0); } ///< pointer to the next chunk
    void *reserve(size_t chunkSize); ///< reserve and return the next chunk

    /// common path of all segment names in path-based environments
    static const char *BasePath;

    /// concatenates parts of a name to form a complete name (or its prefix)
    static SBuf Name(const SBuf &prefix, const char *suffix);

private:

    // not implemented
    Segment(const Segment &);
    Segment &operator =(const Segment &);

#if HAVE_SHM

    bool createFresh(int &err);
    void attach();
    void detach();
    void lock();
    void unlink(); ///< unlink the segment
    off_t statSize(const char *context) const;

    static String GenerateName(const char *id);

    int theFD; ///< shared memory segment file descriptor

#else // HAVE_SHM

    void checkSupport(const char *const context);

#endif // HAVE_SHM

    const String theName; ///< shared memory segment file name
    void *theMem; ///< pointer to mmapped shared memory segment
    off_t theSize; ///< shared memory segment size
    off_t theReserved; ///< the total number of reserve()d bytes
    bool doUnlink; ///< whether the segment should be unlinked on destruction
};

/// Base class for runners that create and open shared memory segments.
/// First may run create() method and then open().
class RegisteredRunner: public ::RegisteredRunner
{
public:
    /* RegisteredRunner API */
    virtual void useConfig();

protected:
    /// called when the runner should create a new memory segment
    virtual void create() = 0;
    /// called when the runner should open a previously created segment,
    /// not needed if segments are opened in constructor or init methods
    virtual void open() {}
};

} // namespace Mem

} // namespace Ipc

#endif /* SQUID_IPC_MEM_SEGMENT_H */

