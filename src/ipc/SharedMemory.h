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
    /// Create a shared memory segment. Id is a human-readable name,
    /// optional magic is unique key (e.g. kid id).
    SharedMemory(const String &id, const int magic = 0);
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

    static String GenerateName(const String &id, const int magic);

    const String theName; ///< shared memory segment file name
    int theFD; ///< shared memory segment file descriptor
    int theSize; ///< shared memory segment size
    void *theMem; ///< pointer to mmapped shared memory segment
};

#endif /* SQUID_IPC_SHARED_MEMORY_H */
