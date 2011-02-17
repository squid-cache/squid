/*
 * $Id$
 *
 */

#ifndef SQUID_IPC_SHARED_MEMORY_H
#define SQUID_IPC_SHARED_MEMORY_H

#include "SquidString.h"

/// POSIX shared memory segment
class SharedMemory {
public:
    /// Create a shared memory segment.
    SharedMemory(const char *const id);
    ~SharedMemory();

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

#endif /* SQUID_IPC_SHARED_MEMORY_H */
