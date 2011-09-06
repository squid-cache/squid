/*
 * $Id$
 *
 */

#ifndef SQUID_IPC_MEM_SEGMENT_H
#define SQUID_IPC_MEM_SEGMENT_H

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

    /// Create a new shared memory segment. Fails if a segment with
    /// the same name already exists. Unlinks the segment on destruction.
    void create(const off_t aSize);
    void open(); ///< Open an existing shared memory segment.

    const String &name() { return theName; } ///< shared memory segment name
    off_t size() { return theSize; } ///< shared memory segment size
    void *mem() { return reserve(0); } ///< pointer to the next chunk
    void *reserve(size_t chunkSize); ///< reserve and return the next chunk


private:
    void attach();
    void detach();
    void unlink(); ///< unlink the segment
    off_t statSize(const char *context) const;

    static String GenerateName(const char *id);

    // not implemented
    Segment(const Segment &);
    Segment &operator =(const Segment &);

    const String theName; ///< shared memory segment file name
    int theFD; ///< shared memory segment file descriptor
    void *theMem; ///< pointer to mmapped shared memory segment
    off_t theSize; ///< shared memory segment size
    off_t theReserved; ///< the total number of reserve()d bytes
    bool doUnlink; ///< whether the segment should be unlinked on destruction
};

} // namespace Mem

} // namespace Ipc

#endif /* SQUID_IPC_MEM_SEGMENT_H */
