/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"

#include "ipc/SharedMemory.h"
#include "protos.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

SharedMemory::SharedMemory(const String &id, const int magic):
    theName(GenerateName(id, magic)), theFD(-1), theSize(-1), theMem(NULL)
{
}

SharedMemory::~SharedMemory() {
    if (theFD >= 0) {
        detach();
        if (close(theFD))
            debugs(54, 5, "SharedMemory::~SharedMemory: close: " << xstrerror());
    }
}

void
SharedMemory::create(const int aSize)
{
    assert(aSize > 0);
    assert(theFD < 0);

    theFD = shm_open(theName.termedBuf(), O_CREAT | O_EXCL | O_RDWR,
                     S_IRUSR | S_IWUSR);
    if (theFD < 0) {
        debugs(54, 5, "SharedMemory::create: shm_open: " << xstrerror());
        fatal("SharedMemory::create failed");
    }

    if (ftruncate(theFD, aSize)) {
        debugs(54, 5, "SharedMemory::create: ftruncate: " << xstrerror());
        fatal("SharedMemory::create failed");
    }

    theSize = aSize;

    attach();
}

void
SharedMemory::open()
{
    assert(theFD < 0);

    theFD = shm_open(theName.termedBuf(), O_RDWR, 0);
    if (theFD < 0) {
        debugs(54, 5, "SharedMemory::open: shm_open: " << xstrerror());
        fatal("SharedMemory::open failed");
    }

    {
        struct stat s;
        memset(&s, 0, sizeof(s));
        if (fstat(theFD, &s)) {
            debugs(54, 5, "SharedMemory::open: fstat: " << xstrerror());
            fatal("SharedMemory::open failed");
        }

        theSize = s.st_size;
    }

    attach();
}

/// Map the shared memory segment to the process memory space.
void
SharedMemory::attach()
{
    assert(theFD >= 0);
    assert(theSize >= 0);
    assert(!theMem);

    void *const p =
        mmap(NULL, theSize, PROT_READ | PROT_WRITE, MAP_SHARED, theFD, 0);
    if (p == MAP_FAILED) {
        debugs(54, 5, "SharedMemory::mmap: mmap: " << xstrerror());
        fatal("SharedMemory::mmap failed");
    }
    theMem = p;
}

/// Unmap the shared memory segment from the process memory space.
void
SharedMemory::detach()
{
    if (!theMem)
        return;

    if (munmap(theMem, theSize)) {
        debugs(54, 5, "SharedMemory::munmap: munmap: " << xstrerror());
        fatal("SharedMemory::munmap failed");
    }
    theMem = 0;
}

/// Generate name for shared memory segment. Uses the master process
/// PID to avoid conflicts with other Squid instances.
String
SharedMemory::GenerateName(const String &id, const int magic)
{
    String name("/squid-");
    name.append(id);
    name.append('-');
    {
        const int pid = IamMasterProcess() ? getpid() : getppid();
        name.append(pid);
    }
    if (magic) {
        name.append('-');
        name.append(magic);
    }
    return name;
}
