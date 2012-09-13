/*
 * DEBUG: section 79    Disk IO Routines
 */

#include "squid.h"
#include "disk.h"
#include "fs/rock/RockRebuild.h"
#include "fs/rock/RockSwapDir.h"
#include "fs/rock/RockDbCell.h"
#include "globals.h"
#include "md5.h"
#include "tools.h"
#include "typedefs.h"
#include "SquidTime.h"
#include "store_rebuild.h"

#if HAVE_ERRNO_H
#include <errno.h>
#endif

CBDATA_NAMESPACED_CLASS_INIT(Rock, Rebuild);

Rock::Rebuild::Rebuild(SwapDir *dir): AsyncJob("Rock::Rebuild"),
        sd(dir),
        dbSize(0),
        dbEntrySize(0),
        dbEntryLimit(0),
        fd(-1),
        dbOffset(0),
        filen(0)
{
    assert(sd);
    memset(&counts, 0, sizeof(counts));
    dbSize = sd->diskOffsetLimit(); // we do not care about the trailer waste
    dbEntrySize = sd->max_objsize;
    dbEntryLimit = sd->entryLimit();
}

Rock::Rebuild::~Rebuild()
{
    if (fd >= 0)
        file_close(fd);
}

/// prepares and initiates entry loading sequence
void
Rock::Rebuild::start()
{
    // in SMP mode, only the disker is responsible for populating the map
    if (UsingSmp() && !IamDiskProcess()) {
        debugs(47, 2, "Non-disker skips rebuilding of cache_dir #" <<
               sd->index << " from " << sd->filePath);
        mustStop("non-disker");
        return;
    }

    debugs(47, DBG_IMPORTANT, "Loading cache_dir #" << sd->index <<
           " from " << sd->filePath);

    fd = file_open(sd->filePath, O_RDONLY | O_BINARY);
    if (fd < 0)
        failure("cannot open db", errno);

    char buf[SwapDir::HeaderSize];
    if (read(fd, buf, sizeof(buf)) != SwapDir::HeaderSize)
        failure("cannot read db header", errno);

    dbOffset = SwapDir::HeaderSize;
    filen = 0;

    checkpoint();
}

/// continues after a pause if not done
void
Rock::Rebuild::checkpoint()
{
    if (!done())
        eventAdd("Rock::Rebuild", Rock::Rebuild::Steps, this, 0.01, 1, true);
}

bool
Rock::Rebuild::doneAll() const
{
    return dbOffset >= dbSize && AsyncJob::doneAll();
}

void
Rock::Rebuild::Steps(void *data)
{
    // use async call to enable job call protection that time events lack
    CallJobHere(47, 5, static_cast<Rebuild*>(data), Rock::Rebuild, steps);
}

void
Rock::Rebuild::steps()
{
    debugs(47,5, HERE << sd->index << " filen " << filen << " at " <<
           dbOffset << " <= " << dbSize);

    // Balance our desire to maximize the number of entries processed at once
    // (and, hence, minimize overheads and total rebuild time) with a
    // requirement to also process Coordinator events, disk I/Os, etc.
    const int maxSpentMsec = 50; // keep small: most RAM I/Os are under 1ms
    const timeval loopStart = current_time;

    int loaded = 0;
    while (loaded < dbEntryLimit && dbOffset < dbSize) {
        doOneEntry();
        dbOffset += dbEntrySize;
        ++filen;
        ++loaded;

        if (counts.scancount % 1000 == 0)
            storeRebuildProgress(sd->index, dbEntryLimit, counts.scancount);

        if (opt_foreground_rebuild)
            continue; // skip "few entries at a time" check below

        getCurrentTime();
        const double elapsedMsec = tvSubMsec(loopStart, current_time);
        if (elapsedMsec > maxSpentMsec || elapsedMsec < 0) {
            debugs(47, 5, HERE << "pausing after " << loaded << " entries in " <<
                   elapsedMsec << "ms; " << (elapsedMsec/loaded) << "ms per entry");
            break;
        }
    }

    checkpoint();
}

void
Rock::Rebuild::doOneEntry()
{
    debugs(47,5, HERE << sd->index << " filen " << filen << " at " <<
           dbOffset << " <= " << dbSize);

    ++counts.scancount;

    if (lseek(fd, dbOffset, SEEK_SET) < 0)
        failure("cannot seek to db entry", errno);

    MemBuf buf;
    buf.init(SM_PAGE_SIZE, SM_PAGE_SIZE);

    if (!storeRebuildLoadEntry(fd, sd->index, buf, counts))
        return;

    // get our header
    DbCellHeader header;
    if (buf.contentSize() < static_cast<mb_size_t>(sizeof(header))) {
        debugs(47, DBG_IMPORTANT, "WARNING: cache_dir[" << sd->index << "]: " <<
               "Ignoring truncated cache entry meta data at " << dbOffset);
        ++counts.invalid;
        return;
    }
    memcpy(&header, buf.content(), sizeof(header));

    if (!header.sane()) {
        debugs(47, DBG_IMPORTANT, "WARNING: cache_dir[" << sd->index << "]: " <<
               "Ignoring malformed cache entry meta data at " << dbOffset);
        ++counts.invalid;
        return;
    }
    buf.consume(sizeof(header)); // optimize to avoid memmove()

    cache_key key[SQUID_MD5_DIGEST_LENGTH];
    StoreEntry loadedE;
    if (!storeRebuildParseEntry(buf, loadedE, key, counts, header.payloadSize)) {
        // skip empty slots
        if (loadedE.swap_filen > 0 || loadedE.swap_file_sz > 0) {
            ++counts.invalid;
            //sd->unlink(filen); leave garbage on disk, it should not hurt
        }
        return;
    }

    assert(loadedE.swap_filen < dbEntryLimit);
    if (!storeRebuildKeepEntry(loadedE, key, counts))
        return;

    ++counts.objcount;
    // loadedE->dump(5);

    sd->addEntry(filen, header, loadedE);
}

void
Rock::Rebuild::swanSong()
{
    debugs(47,3, HERE << "cache_dir #" << sd->index << " rebuild level: " <<
           StoreController::store_dirs_rebuilding);
    --StoreController::store_dirs_rebuilding;
    storeRebuildComplete(&counts);
}

void
Rock::Rebuild::failure(const char *msg, int errNo)
{
    debugs(47,5, HERE << sd->index << " filen " << filen << " at " <<
           dbOffset << " <= " << dbSize);

    if (errNo)
        debugs(47, DBG_CRITICAL, "ERROR: Rock cache_dir rebuild failure: " << xstrerr(errNo));
    debugs(47, DBG_CRITICAL, "Do you need to run 'squid -z' to initialize storage?");

    assert(sd);
    fatalf("Rock cache_dir[%d] rebuild of %s failed: %s.",
           sd->index, sd->filePath, msg);
}
