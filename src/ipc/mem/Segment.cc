/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/TextException.h"
#include "compat/shm.h"
#include "Debug.h"
#include "fatal.h"
#include "ipc/mem/Segment.h"
#include "SBuf.h"
#include "tools.h"

#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

// test cases change this
const char *Ipc::Mem::Segment::BasePath = DEFAULT_STATEDIR;

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

SBuf
Ipc::Mem::Segment::Name(const SBuf &prefix, const char *suffix)
{
    SBuf result = prefix;
    result.append("_");
    result.append(suffix);
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

    // Why a brand new segment? A Squid crash may leave a reusable segment, but
    // our placement-new code requires an all-0s segment. We could truncate and
    // resize the old segment, but OS X does not allow using O_TRUNC with
    // shm_open() and does not support ftruncate() for old segments.
    if (!createFresh() && errno == EEXIST) {
        unlink();
        createFresh();
    }

    if (theFD < 0) {
        debugs(54, 5, HERE << "shm_open " << theName << ": " << xstrerror());
        fatalf("Ipc::Mem::Segment::create failed to shm_open(%s): %s\n",
               theName.termedBuf(), xstrerror());
    }

    if (ftruncate(theFD, aSize)) {
        const int savedError = errno;
        unlink();
        debugs(54, 5, HERE << "ftruncate " << theName << ": " << xstrerr(savedError));
        fatalf("Ipc::Mem::Segment::create failed to ftruncate(%s): %s\n",
               theName.termedBuf(), xstrerr(savedError));
    }
    // We assume that the shm_open(O_CREAT)+ftruncate() combo zeros the segment.

    theSize = statSize("Ipc::Mem::Segment::create");

    // OS X will round up to a full page, so not checking for exact size match.
    assert(theSize >= aSize);

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
        fatalf("Ipc::Mem::Segment::open failed to shm_open(%s): %s\n",
               theName.termedBuf(), xstrerror());
    }

    theSize = statSize("Ipc::Mem::Segment::open");

    debugs(54, 3, HERE << "opened " << theName << " segment: " << theSize);

    attach();
}

/// Creates a brand new shared memory segment and returns true.
/// Fails and returns false if there exist an old segment with the same name.
bool
Ipc::Mem::Segment::createFresh()
{
    theFD = shm_open(theName.termedBuf(),
                     O_EXCL | O_CREAT | O_RDWR,
                     S_IRUSR | S_IWUSR);
    return theFD >= 0;
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
        fatalf("Ipc::Mem::Segment::attach failed to mmap(%s): %s\n",
               theName.termedBuf(), xstrerror());
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
        fatalf("Ipc::Mem::Segment::detach failed to munmap(%s): %s\n",
               theName.termedBuf(), xstrerror());
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
        debugs(54, 5, HERE << context << " fstat " << theName << ": " << xstrerror());
        fatalf("Ipc::Mem::Segment::statSize: %s failed to fstat(%s): %s\n",
               context, theName.termedBuf(), xstrerror());
    }

    return s.st_size;
}

/// Generate name for shared memory segment. Starts with a prefix required
/// for cross-platform portability and replaces all slashes in ID with dots.
String
Ipc::Mem::Segment::GenerateName(const char *id)
{
    assert(BasePath && *BasePath);
    static const bool nameIsPath = shm_portable_segment_name_is_path();
    String name;
    if (nameIsPath) {
        name.append(BasePath);
        if (name[name.size()-1] != '/')
            name.append('/');
    } else {
        name.append('/');
        name.append(service_name.c_str());
        name.append('-');
    }

    // append id, replacing slashes with dots
    for (const char *slash = strchr(id, '/'); slash; slash = strchr(id, '/')) {
        if (id != slash) {
            name.append(id, slash - id);
            name.append('.');
        }
        id = slash + 1;
    }
    name.append(id);

    name.append(".shm"); // to distinguish from non-segments when nameIsPath
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
        theMem = NULL;
        Segments.erase(theName);
        debugs(54, 3, HERE << "unlinked " << theName << " fake segment");
    }
}

bool
Ipc::Mem::Segment::Enabled()
{
    return !UsingSmp() && IamWorkerProcess();
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
        debugs(54, 5, HERE << context <<
               ": True shared memory segments are not supported. "
               "Cannot fake shared segments in SMP config.");
        fatalf("Ipc::Mem::Segment: Cannot fake shared segments in SMP config (%s)\n",
               context);
    }
}

#endif // HAVE_SHM

void
Ipc::Mem::RegisteredRunner::useConfig()
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
        create();

    // we assume that master process does not need shared segments
    // unless it is also a worker
    if (!InDaemonMode() || !IamMasterProcess())
        open();
}

