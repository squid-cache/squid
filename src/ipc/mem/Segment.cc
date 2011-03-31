/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"

#include "ipc/mem/Segment.h"
#include "protos.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

Ipc::Mem::Segment::Segment(const char *const id):
    theName(GenerateName(id)), theFD(-1), theSize(-1), theMem(NULL)
{
}

Ipc::Mem::Segment::~Segment() {
    if (theFD >= 0) {
        detach();
        if (close(theFD) != 0)
            debugs(54, 5, HERE << "close: " << xstrerror());
    }
}

void
Ipc::Mem::Segment::create(const int aSize)
{
    assert(aSize > 0);
    assert(theFD < 0);

    theFD = shm_open(theName.termedBuf(), O_CREAT | O_RDWR | O_TRUNC,
                     S_IRUSR | S_IWUSR);
    if (theFD < 0) {
        debugs(54, 5, HERE << "shm_open: " << xstrerror());
        fatal("Ipc::Mem::Segment::create failed to shm_open");
    }

    if (ftruncate(theFD, aSize)) {
        debugs(54, 5, HERE << "ftruncate: " << xstrerror());
        fatal("Ipc::Mem::Segment::create failed to ftruncate");
    }

    theSize = aSize;

    attach();
}

void
Ipc::Mem::Segment::open()
{
    assert(theFD < 0);

    theFD = shm_open(theName.termedBuf(), O_RDWR, 0);
    if (theFD < 0) {
        debugs(54, 5, HERE << "shm_open: " << xstrerror());
        String s = "Ipc::Mem::Segment::open failed to shm_open";
        s.append(theName);
        fatal(s.termedBuf());
    }

    {
        struct stat s;
        memset(&s, 0, sizeof(s));
        if (fstat(theFD, &s)) {
            debugs(54, 5, HERE << "fstat: " << xstrerror());
        String s = "Ipc::Mem::Segment::open failed to fstat";
        s.append(theName);
        fatal(s.termedBuf());
        }

        theSize = s.st_size;
    }

    attach();
}

/// Map the shared memory segment to the process memory space.
void
Ipc::Mem::Segment::attach()
{
    assert(theFD >= 0);
    assert(theSize >= 0);
    assert(!theMem);

    void *const p =
        mmap(NULL, theSize, PROT_READ | PROT_WRITE, MAP_SHARED, theFD, 0);
    if (p == MAP_FAILED) {
        debugs(54, 5, HERE << "mmap: " << xstrerror());
        fatal("Ipc::Mem::Segment::attach failed to mmap");
    }
    theMem = p;
}

/// Unmap the shared memory segment from the process memory space.
void
Ipc::Mem::Segment::detach()
{
    if (!theMem)
        return;

    if (munmap(theMem, theSize)) {
        debugs(54, 5, HERE << "munmap: " << xstrerror());
        fatal("Ipc::Mem::Segment::detach failed to munmap");
    }
    theMem = 0;
}

/// Generate name for shared memory segment. Replaces all slashes with dots.
String
Ipc::Mem::Segment::GenerateName(const char *id)
{
    String name("/squid-");
    for (const char *slash = strchr(id, '/'); slash; slash = strchr(id, '/')) {
        if (id != slash) {
            name.append(id, slash - id);
            name.append('.');
        }
        id = slash + 1;
    }
    name.append(id);
    return name;
}
