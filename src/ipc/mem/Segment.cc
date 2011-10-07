/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"
#include "base/TextException.h"
#include "compat/shm.h"
#include "ipc/mem/Segment.h"
#include "protos.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

void *
Ipc::Mem::Segment::reserve(size_t chunkSize)
{
    Must(theMem);
    // check for overflows
    // chunkSize >= 0 may result in warnings on systems where off_t is unsigned
    assert(!chunkSize || static_cast<off_t>(chunkSize) > 0);
    assert(static_cast<off_t>(chunkSize) <= theSize);
    assert(theReserved <= theSize - static_cast<off_t>(chunkSize));
    void *result = reinterpret_cast<char*>(theMem) + theReserved;
    theReserved += chunkSize;
    return result;
}

#if HAVE_SHM

Ipc::Mem::Segment::Segment(const char *const id):
        theFD(-1), theName(GenerateName(id)), theMem(NULL),
        theSize(0), theReserved(0), doUnlink(false)
{
}

Ipc::Mem::Segment::~Segment()
{
    if (theFD >= 0) {
        detach();
        if (close(theFD) != 0)
            debugs(54, 5, HERE << "close " << theName << ": " << xstrerror());
    }
    if (doUnlink)
        unlink();
}

// fake Ipc::Mem::Segment::Enabled (!HAVE_SHM) is more selective
bool
Ipc::Mem::Segment::Enabled()
{
    return true;
}

void
Ipc::Mem::Segment::create(const off_t aSize)
{
    assert(aSize > 0);
    assert(theFD < 0);

    theFD = shm_open(theName.termedBuf(), O_CREAT | O_RDWR | O_TRUNC,
                     S_IRUSR | S_IWUSR);
    if (theFD < 0) {
        debugs(54, 5, HERE << "shm_open " << theName << ": " << xstrerror());
        fatal("Ipc::Mem::Segment::create failed to shm_open");
    }

    if (ftruncate(theFD, aSize)) {
        debugs(54, 5, HERE << "ftruncate " << theName << ": " << xstrerror());
        fatal("Ipc::Mem::Segment::create failed to ftruncate");
    }

    assert(statSize("Ipc::Mem::Segment::create") == aSize); // paranoid

    theSize = aSize;
    theReserved = 0;
    doUnlink = true;

    debugs(54, 3, HERE << "created " << theName << " segment: " << theSize);

    attach();
}

void
Ipc::Mem::Segment::open()
{
    assert(theFD < 0);

    theFD = shm_open(theName.termedBuf(), O_RDWR, 0);
    if (theFD < 0) {
        debugs(54, 5, HERE << "shm_open " << theName << ": " << xstrerror());
        String s = "Ipc::Mem::Segment::open failed to shm_open ";
        s.append(theName);
        fatal(s.termedBuf());
    }

    theSize = statSize("Ipc::Mem::Segment::open");

    debugs(54, 3, HERE << "opened " << theName << " segment: " << theSize);

    attach();
}

/// Map the shared memory segment to the process memory space.
void
Ipc::Mem::Segment::attach()
{
    assert(theFD >= 0);
    assert(!theMem);

    // mmap() accepts size_t for the size; we give it off_t which might
    // be bigger; assert overflows until we support multiple mmap()s?
    assert(theSize == static_cast<off_t>(static_cast<size_t>(theSize)));

    void *const p =
        mmap(NULL, theSize, PROT_READ | PROT_WRITE, MAP_SHARED, theFD, 0);
    if (p == MAP_FAILED) {
        debugs(54, 5, HERE << "mmap " << theName << ": " << xstrerror());
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
        debugs(54, 5, HERE << "munmap " << theName << ": " << xstrerror());
        fatal("Ipc::Mem::Segment::detach failed to munmap");
    }
    theMem = 0;
}

void
Ipc::Mem::Segment::unlink()
{
    if (shm_unlink(theName.termedBuf()) != 0)
        debugs(54, 5, HERE << "shm_unlink(" << theName << "): " << xstrerror());
    else
        debugs(54, 3, HERE << "unlinked " << theName << " segment");
}

/// determines the size of the underlying "file"
off_t
Ipc::Mem::Segment::statSize(const char *context) const
{
    Must(theFD >= 0);

    struct stat s;
    memset(&s, 0, sizeof(s));

    if (fstat(theFD, &s) != 0) {
        debugs(54, 5, HERE << "fstat " << theName << ": " << xstrerror());
        String s = context;
        s.append("failed to fstat(2) ");
        s.append(theName);
        fatal(s.termedBuf());
    }

    return s.st_size;
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

#else // HAVE_SHM

#include <map>

typedef std::map<String, Ipc::Mem::Segment *> SegmentMap;
static SegmentMap Segments;

Ipc::Mem::Segment::Segment(const char *const id):
        theName(id), theMem(NULL), theSize(0), theReserved(0), doUnlink(false)
{
}

Ipc::Mem::Segment::~Segment()
{
    if (doUnlink) {
        delete [] static_cast<char *>(theMem);
        debugs(54, 3, HERE << "deleted " << theName << " segment");
    }
}

bool
Ipc::Mem::Segment::Enabled()
{
    return !InDaemonMode() || (!UsingSmp() && IamWorkerProcess());
}

void
Ipc::Mem::Segment::create(const off_t aSize)
{
    assert(aSize > 0);
    assert(!theMem);
    checkSupport("Fake segment creation");

    const bool inserted = Segments.insert(std::make_pair(theName, this)).second;
    if (!inserted)
        fatalf("Duplicate fake segment creation: %s", theName.termedBuf());

    theMem = new char[aSize];
    theSize = aSize;
    doUnlink = true;

    debugs(54, 3, HERE << "created " << theName << " fake segment: " << theSize);
}

void
Ipc::Mem::Segment::open()
{
    assert(!theMem);
    checkSupport("Fake segment open");

    const SegmentMap::const_iterator i = Segments.find(theName);
    if (i == Segments.end())
        fatalf("Fake segment not found: %s", theName.termedBuf());

    const Segment &segment = *i->second;
    theMem = segment.theMem;
    theSize = segment.theSize;

    debugs(54, 3, HERE << "opened " << theName << " fake segment: " << theSize);
}

void
Ipc::Mem::Segment::checkSupport(const char *const context)
{
    if (!Enabled()) {
        debugs(54, 5, HERE << "True shared memory segments are not supported. "
               "Cannot fake shared segments in SMP config.");
        fatalf("%s failed", context);
    }
}

#endif // HAVE_SHM

void
Ipc::Mem::RegisteredRunner::run(const RunnerRegistry &r)
{
    // If Squid is built with real segments, we create() real segments
    // in the master process only.  Otherwise, we create() fake
    // segments in each worker process.  We assume that only workers
    // need and can work with fake segments.
#if HAVE_SHM
    if (IamMasterProcess())
#else
    if (IamWorkerProcess())
#endif
        create(r);

    // we assume that master process does not need shared segments
    // unless it is also a worker
    if (!InDaemonMode() || !IamMasterProcess())
        open(r);
}
