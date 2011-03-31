/*
 * $Id$
 *
 */

#ifndef SQUID_IPC_MEM_SEGMENT_H
#define SQUID_IPC_MEM_SEGMENT_H

#include "SquidString.h"

namespace Ipc {

namespace Mem {

/// POSIX shared memory segment
class Segment {
public:
    /// Create a shared memory segment.
    Segment(const char *const id);
    ~Segment();

    /// Create a new shared memory segment. Fails if a segment with
    /// the same name already exists.
    void create(const int aSize);
    void open(); ///< Open an existing shared memory segment.

    const String &name() { return theName; } ///< shared memory segment name
    int size() { return theSize; } ///< shared memory segment size
    void *mem() { return theMem; } ///< pointer to mmapped shared memory segment

private:
    void attach();
    void detach();

    static String GenerateName(const char *id);

    const String theName; ///< shared memory segment file name
    int theFD; ///< shared memory segment file descriptor
    int theSize; ///< shared memory segment size
    void *theMem; ///< pointer to mmapped shared memory segment
};

} // namespace Mem

} // namespace Ipc

#endif /* SQUID_IPC_MEM_SEGMENT_H */
