/*
 * $Id$
 *
 * DEBUG: section 79    Disk IO Routines
 */

#include "fs/rock/RockRebuild.h"
#include "fs/rock/RockSwapDir.h"

CBDATA_NAMESPACED_CLASS_INIT(Rock, Rebuild);

Rock::Rebuild::Rebuild(SwapDir *dir):
    sd(dir),
    dbSize(0),
    dbEntrySize(0),
    dbEntryLimit(0),
    fd(-1),
    dbOffset(0),
    fileno(0)
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
Rock::Rebuild::start() {
    debugs(47,2, HERE << sd->index);

    fd = file_open(sd->filePath, O_RDONLY | O_BINARY);
    if (fd < 0)
        failure("cannot open db", errno);

    char buf[SwapDir::HeaderSize];
    if (read(fd, buf, sizeof(buf)) != SwapDir::HeaderSize)
        failure("cannot read db header", errno);

    dbOffset = SwapDir::HeaderSize;
    fileno = 0;    

    checkpoint();
}

/// quits if done; otherwise continues after a pause
void
Rock::Rebuild::checkpoint()
{
    if (dbOffset < dbSize)
        eventAdd("Rock::Rebuild", Rock::Rebuild::Steps, this, 0.01, 1, true);
    else
        complete();
}

void
Rock::Rebuild::Steps(void *data)
{
    static_cast<Rebuild*>(data)->steps();
}

void
Rock::Rebuild::steps() {
    debugs(47,5, HERE << sd->index << " fileno " << fileno << " at " <<
        dbOffset << " <= " << dbSize);

    const int maxCount = dbEntryLimit;
    const int wantedCount = opt_foreground_rebuild ? maxCount : 50;
    const int stepCount = min(wantedCount, maxCount);
    for (int i = 0; i < stepCount && dbOffset < dbSize; ++i, ++fileno) {
        doOneEntry();
        dbOffset += dbEntrySize;

        if (counts.scancount % 1000 == 0)
            storeRebuildProgress(sd->index, maxCount, counts.scancount);
	}

    checkpoint();
}

void
Rock::Rebuild::doOneEntry() {
    debugs(47,5, HERE << sd->index << " fileno " << fileno << " at " <<
        dbOffset << " <= " << dbSize);

    if (lseek(fd, dbOffset, SEEK_SET) < 0)
        failure("cannot seek to db entry", errno);

    cache_key key[SQUID_MD5_DIGEST_LENGTH];
    StoreEntry loadedE;
    if (!storeRebuildLoadEntry(fd, loadedE, key, counts, 0)) {
        // skip empty slots
        if (loadedE.swap_filen > 0 || loadedE.swap_file_sz > 0) {
            counts.invalid++;
            sd->unlink(fileno);
        }
        return;
	}

    assert(loadedE.swap_filen < dbEntryLimit);
    if (!storeRebuildKeepEntry(loadedE, key, counts))
        return;

    counts.objcount++;
    // loadedE->dump(5);

    //StoreEntry *e =
    sd->addEntry(fileno, loadedE);
    //storeDirSwapLog(e, SWAP_LOG_ADD);
}

void
Rock::Rebuild::complete() {
    debugs(47,3, HERE << sd->index);
    close(fd);
    StoreController::store_dirs_rebuilding--;
    storeRebuildComplete(&counts);
    delete this; // same as cbdataFree
}

void
Rock::Rebuild::failure(const char *msg, int errNo) {
    debugs(47,5, HERE << sd->index << " fileno " << fileno << " at " <<
        dbOffset << " <= " << dbSize);

    if (errNo)
        debugs(47,0, "Rock cache_dir rebuild failure: " << xstrerr(errNo));
    debugs(47,0, "Do you need to run 'squid -z' to initialize storage?");

    assert(sd);
    fatalf("Rock cache_dir[%d] rebuild of %s failed: %s.",
        sd->index, sd->filePath, msg);
}
