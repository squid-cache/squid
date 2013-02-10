/*
 * DEBUG: section 47    Store Directory Routines
 */

#include "squid.h"
#include "cache_cf.h"
#include "ConfigOption.h"
#include "DiskIO/DiskIOModule.h"
#include "DiskIO/DiskIOStrategy.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
#include "fs/rock/RockSwapDir.h"
#include "fs/rock/RockIoState.h"
#include "fs/rock/RockIoRequests.h"
#include "fs/rock/RockRebuild.h"
#include "globals.h"
#include "ipc/mem/Pages.h"
#include "MemObject.h"
#include "Parsing.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "tools.h"

#include <cstdlib>
#include <iomanip>

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

const int64_t Rock::SwapDir::HeaderSize = 16*1024;

Rock::SwapDir::SwapDir(): ::SwapDir("rock"), filePath(NULL), io(NULL), map(NULL)
{
}

Rock::SwapDir::~SwapDir()
{
    delete io;
    delete map;
    safe_free(filePath);
}

StoreSearch *
Rock::SwapDir::search(String const url, HttpRequest *)
{
    assert(false);
    return NULL; // XXX: implement
}

void
Rock::SwapDir::get(String const key, STOREGETCLIENT cb, void *data)
{
    ::SwapDir::get(key, cb, data);
}

// called when Squid core needs a StoreEntry with a given key
StoreEntry *
Rock::SwapDir::get(const cache_key *key)
{
    if (!map || !theFile || !theFile->canRead())
        return NULL;

    sfileno filen;
    const Ipc::StoreMapSlot *const slot = map->openForReading(key, filen);
    if (!slot)
        return NULL;

    const Ipc::StoreMapSlot::Basics &basics = slot->basics;

    // create a brand new store entry and initialize it with stored basics
    StoreEntry *e = new StoreEntry();
    e->lock_count = 0;
    e->swap_dirn = index;
    e->swap_filen = filen;
    e->swap_file_sz = basics.swap_file_sz;
    e->lastref = basics.lastref;
    e->timestamp = basics.timestamp;
    e->expires = basics.expires;
    e->lastmod = basics.lastmod;
    e->refcount = basics.refcount;
    e->flags = basics.flags;
    e->store_status = STORE_OK;
    e->setMemStatus(NOT_IN_MEMORY);
    e->swap_status = SWAPOUT_DONE;
    e->ping_status = PING_NONE;
    EBIT_SET(e->flags, ENTRY_CACHABLE);
    EBIT_CLR(e->flags, RELEASE_REQUEST);
    EBIT_CLR(e->flags, KEY_PRIVATE);
    EBIT_SET(e->flags, ENTRY_VALIDATED);
    e->hashInsert(key);
    trackReferences(*e);

    return e;
    // the disk entry remains open for reading, protected from modifications
}

void Rock::SwapDir::disconnect(StoreEntry &e)
{
    assert(e.swap_dirn == index);
    assert(e.swap_filen >= 0);
    // cannot have SWAPOUT_NONE entry with swap_filen >= 0
    assert(e.swap_status != SWAPOUT_NONE);

    // do not rely on e.swap_status here because there is an async delay
    // before it switches from SWAPOUT_WRITING to SWAPOUT_DONE.

    // since e has swap_filen, its slot is locked for either reading or writing
    map->abortIo(e.swap_filen);
    e.swap_dirn = -1;
    e.swap_filen = -1;
    e.swap_status = SWAPOUT_NONE;
}

uint64_t
Rock::SwapDir::currentSize() const
{
    return HeaderSize + max_objsize * currentCount();
}

uint64_t
Rock::SwapDir::currentCount() const
{
    return map ? map->entryCount() : 0;
}

/// In SMP mode only the disker process reports stats to avoid
/// counting the same stats by multiple processes.
bool
Rock::SwapDir::doReportStat() const
{
    return ::SwapDir::doReportStat() && (!UsingSmp() || IamDiskProcess());
}

void
Rock::SwapDir::swappedOut(const StoreEntry &)
{
    // stats are not stored but computed when needed
}

int64_t
Rock::SwapDir::entryLimitAllowed() const
{
    const int64_t eLimitLo = map ? map->entryLimit() : 0; // dynamic shrinking unsupported
    const int64_t eWanted = (maxSize() - HeaderSize)/maxObjectSize();
    return min(max(eLimitLo, eWanted), entryLimitHigh());
}

// TODO: encapsulate as a tool; identical to CossSwapDir::create()
void
Rock::SwapDir::create()
{
    assert(path);
    assert(filePath);

    if (UsingSmp() && !IamDiskProcess()) {
        debugs (47,3, HERE << "disker will create in " << path);
        return;
    }

    debugs (47,3, HERE << "creating in " << path);

    struct stat dir_sb;
    if (::stat(path, &dir_sb) == 0) {
        struct stat file_sb;
        if (::stat(filePath, &file_sb) == 0) {
            debugs (47, DBG_IMPORTANT, "Skipping existing Rock db: " << filePath);
            return;
        }
        // else the db file is not there or is not accessible, and we will try
        // to create it later below, generating a detailed error on failures.
    } else { // path does not exist or is inaccessible
        // If path exists but is not accessible, mkdir() below will fail, and
        // the admin should see the error and act accordingly, so there is
        // no need to distinguish ENOENT from other possible stat() errors.
        debugs (47, DBG_IMPORTANT, "Creating Rock db directory: " << path);
        const int res = mkdir(path, 0700);
        if (res != 0) {
            debugs(47, DBG_CRITICAL, "Failed to create Rock db dir " << path <<
                   ": " << xstrerror());
            fatal("Rock Store db creation error");
        }
    }

    debugs (47, DBG_IMPORTANT, "Creating Rock db: " << filePath);
#if SLOWLY_FILL_WITH_ZEROS
    char block[1024];
    Must(maxSize() % sizeof(block) == 0);
    memset(block, '\0', sizeof(block));

    const int swap = open(filePath, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0600);
    for (off_t offset = 0; offset < maxSize(); offset += sizeof(block)) {
        if (write(swap, block, sizeof(block)) != sizeof(block)) {
            debugs(47, DBG_CRITICAL, "ERROR: Failed to create Rock Store db in " << filePath <<
                   ": " << xstrerror());
            fatal("Rock Store db creation error");
        }
    }
    close(swap);
#else
    const int swap = open(filePath, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0600);
    if (swap < 0) {
        debugs(47, DBG_CRITICAL, "ERROR: Failed to initialize Rock Store db in " << filePath <<
               "; create error: " << xstrerror());
        fatal("Rock Store db creation error");
    }

    if (ftruncate(swap, maxSize()) != 0) {
        debugs(47, DBG_CRITICAL, "ERROR: Failed to initialize Rock Store db in " << filePath <<
               "; truncate error: " << xstrerror());
        fatal("Rock Store db creation error");
    }

    char header[HeaderSize];
    memset(header, '\0', sizeof(header));
    if (write(swap, header, sizeof(header)) != sizeof(header)) {
        debugs(47, DBG_CRITICAL, "ERROR: Failed to initialize Rock Store db in " << filePath <<
               "; write error: " << xstrerror());
        fatal("Rock Store db initialization error");
    }
    close(swap);
#endif
}

void
Rock::SwapDir::init()
{
    debugs(47,2, HERE);

    // XXX: SwapDirs aren't refcounted. We make IORequestor calls, which
    // are refcounted. We up our count once to avoid implicit delete's.
    lock();

    Must(!map);
    map = new DirMap(path);

    const char *ioModule = needsDiskStrand() ? "IpcIo" : "Blocking";
    if (DiskIOModule *m = DiskIOModule::Find(ioModule)) {
        debugs(47,2, HERE << "Using DiskIO module: " << ioModule);
        io = m->createStrategy();
        io->init();
    } else {
        debugs(47, DBG_CRITICAL, "FATAL: Rock store is missing DiskIO module: " <<
               ioModule);
        fatal("Rock Store missing a required DiskIO module");
    }

    theFile = io->newFile(filePath);
    theFile->configure(fileConfig);
    theFile->open(O_RDWR, 0644, this);

    // Increment early. Otherwise, if one SwapDir finishes rebuild before
    // others start, storeRebuildComplete() will think the rebuild is over!
    // TODO: move store_dirs_rebuilding hack to store modules that need it.
    ++StoreController::store_dirs_rebuilding;
}

bool
Rock::SwapDir::needsDiskStrand() const
{
    const bool wontEvenWorkWithoutDisker = Config.workers > 1;
    const bool wouldWorkBetterWithDisker = DiskIOModule::Find("IpcIo");
    return InDaemonMode() && (wontEvenWorkWithoutDisker ||
                              wouldWorkBetterWithDisker);
}

void
Rock::SwapDir::parse(int anIndex, char *aPath)
{
    index = anIndex;

    path = xstrdup(aPath);

    // cache store is located at path/db
    String fname(path);
    fname.append("/rock");
    filePath = xstrdup(fname.termedBuf());

    parseSize(false);
    parseOptions(0);

    // Current openForWriting() code overwrites the old slot if needed
    // and possible, so proactively removing old slots is probably useless.
    assert(!repl); // repl = createRemovalPolicy(Config.replPolicy);

    validateOptions();
}

void
Rock::SwapDir::reconfigure()
{
    parseSize(true);
    parseOptions(1);
    // TODO: can we reconfigure the replacement policy (repl)?
    validateOptions();
}

/// parse maximum db disk size
void
Rock::SwapDir::parseSize(const bool reconfig)
{
    const int i = GetInteger();
    if (i < 0)
        fatal("negative Rock cache_dir size value");
    const uint64_t new_max_size =
        static_cast<uint64_t>(i) << 20; // MBytes to Bytes
    if (!reconfig)
        max_size = new_max_size;
    else if (new_max_size != max_size) {
        debugs(3, DBG_IMPORTANT, "WARNING: cache_dir '" << path << "' size "
               "cannot be changed dynamically, value left unchanged (" <<
               (max_size >> 20) << " MB)");
    }
}

ConfigOption *
Rock::SwapDir::getOptionTree() const
{
    ConfigOptionVector *vector = dynamic_cast<ConfigOptionVector*>(::SwapDir::getOptionTree());
    assert(vector);
    vector->options.push_back(new ConfigOptionAdapter<SwapDir>(*const_cast<SwapDir *>(this), &SwapDir::parseTimeOption, &SwapDir::dumpTimeOption));
    vector->options.push_back(new ConfigOptionAdapter<SwapDir>(*const_cast<SwapDir *>(this), &SwapDir::parseRateOption, &SwapDir::dumpRateOption));
    return vector;
}

bool
Rock::SwapDir::allowOptionReconfigure(const char *const option) const
{
    return strcmp(option, "max-size") != 0 &&
           ::SwapDir::allowOptionReconfigure(option);
}

/// parses time-specific options; mimics ::SwapDir::optionObjectSizeParse()
bool
Rock::SwapDir::parseTimeOption(char const *option, const char *value, int reconfig)
{
    // TODO: ::SwapDir or, better, Config should provide time-parsing routines,
    // including time unit handling. Same for size.

    time_msec_t *storedTime;
    if (strcmp(option, "swap-timeout") == 0)
        storedTime = &fileConfig.ioTimeout;
    else
        return false;

    if (!value)
        self_destruct();

    // TODO: handle time units and detect parsing errors better
    const int64_t parsedValue = strtoll(value, NULL, 10);
    if (parsedValue < 0) {
        debugs(3, DBG_CRITICAL, "FATAL: cache_dir " << path << ' ' << option << " must not be negative but is: " << parsedValue);
        self_destruct();
    }

    const time_msec_t newTime = static_cast<time_msec_t>(parsedValue);

    if (!reconfig)
        *storedTime = newTime;
    else if (*storedTime != newTime) {
        debugs(3, DBG_IMPORTANT, "WARNING: cache_dir " << path << ' ' << option
               << " cannot be changed dynamically, value left unchanged: " <<
               *storedTime);
    }

    return true;
}

/// reports time-specific options; mimics ::SwapDir::optionObjectSizeDump()
void
Rock::SwapDir::dumpTimeOption(StoreEntry * e) const
{
    if (fileConfig.ioTimeout)
        storeAppendPrintf(e, " swap-timeout=%" PRId64,
                          static_cast<int64_t>(fileConfig.ioTimeout));
}

/// parses rate-specific options; mimics ::SwapDir::optionObjectSizeParse()
bool
Rock::SwapDir::parseRateOption(char const *option, const char *value, int isaReconfig)
{
    int *storedRate;
    if (strcmp(option, "max-swap-rate") == 0)
        storedRate = &fileConfig.ioRate;
    else
        return false;

    if (!value)
        self_destruct();

    // TODO: handle time units and detect parsing errors better
    const int64_t parsedValue = strtoll(value, NULL, 10);
    if (parsedValue < 0) {
        debugs(3, DBG_CRITICAL, "FATAL: cache_dir " << path << ' ' << option << " must not be negative but is: " << parsedValue);
        self_destruct();
    }

    const int newRate = static_cast<int>(parsedValue);

    if (newRate < 0) {
        debugs(3, DBG_CRITICAL, "FATAL: cache_dir " << path << ' ' << option << " must not be negative but is: " << newRate);
        self_destruct();
    }

    if (!isaReconfig)
        *storedRate = newRate;
    else if (*storedRate != newRate) {
        debugs(3, DBG_IMPORTANT, "WARNING: cache_dir " << path << ' ' << option
               << " cannot be changed dynamically, value left unchanged: " <<
               *storedRate);
    }

    return true;
}

/// reports rate-specific options; mimics ::SwapDir::optionObjectSizeDump()
void
Rock::SwapDir::dumpRateOption(StoreEntry * e) const
{
    if (fileConfig.ioRate >= 0)
        storeAppendPrintf(e, " max-swap-rate=%d", fileConfig.ioRate);
}

/// check the results of the configuration; only level-0 debugging works here
void
Rock::SwapDir::validateOptions()
{
    if (max_objsize <= 0)
        fatal("Rock store requires a positive max-size");

    const int64_t maxSizeRoundingWaste = 1024 * 1024; // size is configured in MB
    const int64_t maxObjectSizeRoundingWaste = maxObjectSize();
    const int64_t maxRoundingWaste =
        max(maxSizeRoundingWaste, maxObjectSizeRoundingWaste);
    const int64_t usableDiskSize = diskOffset(entryLimitAllowed());
    const int64_t diskWasteSize = maxSize() - usableDiskSize;
    Must(diskWasteSize >= 0);

    // warn if maximum db size is not reachable due to sfileno limit
    if (entryLimitAllowed() == entryLimitHigh() &&
            diskWasteSize >= maxRoundingWaste) {
        debugs(47, DBG_CRITICAL, "Rock store cache_dir[" << index << "] '" << path << "':");
        debugs(47, DBG_CRITICAL, "\tmaximum number of entries: " << entryLimitAllowed());
        debugs(47, DBG_CRITICAL, "\tmaximum object size: " << maxObjectSize() << " Bytes");
        debugs(47, DBG_CRITICAL, "\tmaximum db size: " << maxSize() << " Bytes");
        debugs(47, DBG_CRITICAL, "\tusable db size:  " << usableDiskSize << " Bytes");
        debugs(47, DBG_CRITICAL, "\tdisk space waste: " << diskWasteSize << " Bytes");
        debugs(47, DBG_CRITICAL, "WARNING: Rock store config wastes space.");
    }
}

void
Rock::SwapDir::rebuild()
{
    //++StoreController::store_dirs_rebuilding; // see Rock::SwapDir::init()
    AsyncJob::Start(new Rebuild(this));
}

/* Add a new object to the cache with empty memory copy and pointer to disk
 * use to rebuild store from disk. Based on UFSSwapDir::addDiskRestore */
bool
Rock::SwapDir::addEntry(const int filen, const DbCellHeader &header, const StoreEntry &from)
{
    debugs(47, 8, HERE << &from << ' ' << from.getMD5Text() <<
           ", filen="<< std::setfill('0') << std::hex << std::uppercase <<
           std::setw(8) << filen);

    sfileno newLocation = 0;
    if (Ipc::StoreMapSlot *slot = map->openForWriting(reinterpret_cast<const cache_key *>(from.key), newLocation)) {
        if (filen == newLocation) {
            slot->set(from);
            map->extras(filen) = header;
        } // else some other, newer entry got into our cell
        map->closeForWriting(newLocation, false);
        return filen == newLocation;
    }

    return false;
}

bool
Rock::SwapDir::canStore(const StoreEntry &e, int64_t diskSpaceNeeded, int &load) const
{
    if (!::SwapDir::canStore(e, sizeof(DbCellHeader)+diskSpaceNeeded, load))
        return false;

    if (!theFile || !theFile->canWrite())
        return false;

    if (!map)
        return false;

    // Do not start I/O transaction if there are less than 10% free pages left.
    // TODO: reserve page instead
    if (needsDiskStrand() &&
            Ipc::Mem::PageLevel(Ipc::Mem::PageId::ioPage) >= 0.9 * Ipc::Mem::PageLimit(Ipc::Mem::PageId::ioPage)) {
        debugs(47, 5, HERE << "too few shared pages for IPC I/O left");
        return false;
    }

    if (io->shedLoad())
        return false;

    load = io->load();
    return true;
}

StoreIOState::Pointer
Rock::SwapDir::createStoreIO(StoreEntry &e, StoreIOState::STFNCB *cbFile, StoreIOState::STIOCB *cbIo, void *data)
{
    if (!theFile || theFile->error()) {
        debugs(47,4, HERE << theFile);
        return NULL;
    }

    // compute payload size for our cell header, using StoreEntry info
    // careful: e.objectLen() may still be negative here
    const int64_t expectedReplySize = e.mem_obj->expectedReplySize();
    assert(expectedReplySize >= 0); // must know to prevent cell overflows
    assert(e.mem_obj->swap_hdr_sz > 0);
    DbCellHeader header;
    header.payloadSize = e.mem_obj->swap_hdr_sz + expectedReplySize;
    const int64_t payloadEnd = sizeof(DbCellHeader) + header.payloadSize;
    assert(payloadEnd <= max_objsize);

    sfileno filen;
    Ipc::StoreMapSlot *const slot =
        map->openForWriting(reinterpret_cast<const cache_key *>(e.key), filen);
    if (!slot) {
        debugs(47, 5, HERE << "map->add failed");
        return NULL;
    }
    e.swap_file_sz = header.payloadSize; // and will be copied to the map
    slot->set(e);
    map->extras(filen) = header;

    // XXX: We rely on our caller, storeSwapOutStart(), to set e.fileno.
    // If that does not happen, the entry will not decrement the read level!

    IoState *sio = new IoState(this, &e, cbFile, cbIo, data);

    sio->swap_dirn = index;
    sio->swap_filen = filen;
    sio->payloadEnd = payloadEnd;
    sio->diskOffset = diskOffset(sio->swap_filen);

    debugs(47,5, HERE << "dir " << index << " created new filen " <<
           std::setfill('0') << std::hex << std::uppercase << std::setw(8) <<
           sio->swap_filen << std::dec << " at " << sio->diskOffset);

    assert(sio->diskOffset + payloadEnd <= diskOffsetLimit());

    sio->file(theFile);

    trackReferences(e);
    return sio;
}

int64_t
Rock::SwapDir::diskOffset(int filen) const
{
    assert(filen >= 0);
    return HeaderSize + max_objsize*filen;
}

int64_t
Rock::SwapDir::diskOffsetLimit() const
{
    assert(map);
    return diskOffset(map->entryLimit());
}

// tries to open an old or being-written-to entry with swap_filen for reading
StoreIOState::Pointer
Rock::SwapDir::openStoreIO(StoreEntry &e, StoreIOState::STFNCB *cbFile, StoreIOState::STIOCB *cbIo, void *data)
{
    if (!theFile || theFile->error()) {
        debugs(47,4, HERE << theFile);
        return NULL;
    }

    if (e.swap_filen < 0) {
        debugs(47,4, HERE << e);
        return NULL;
    }

    // Do not start I/O transaction if there are less than 10% free pages left.
    // TODO: reserve page instead
    if (needsDiskStrand() &&
            Ipc::Mem::PageLevel(Ipc::Mem::PageId::ioPage) >= 0.9 * Ipc::Mem::PageLimit(Ipc::Mem::PageId::ioPage)) {
        debugs(47, 5, HERE << "too few shared pages for IPC I/O left");
        return NULL;
    }

    // The are two ways an entry can get swap_filen: our get() locked it for
    // reading or our storeSwapOutStart() locked it for writing. Peeking at our
    // locked entry is safe, but no support for reading a filling entry.
    const Ipc::StoreMapSlot *slot = map->peekAtReader(e.swap_filen);
    if (!slot)
        return NULL; // we were writing afterall

    IoState *sio = new IoState(this, &e, cbFile, cbIo, data);

    sio->swap_dirn = index;
    sio->swap_filen = e.swap_filen;
    sio->payloadEnd = sizeof(DbCellHeader) + map->extras(e.swap_filen).payloadSize;
    assert(sio->payloadEnd <= max_objsize); // the payload fits the slot

    debugs(47,5, HERE << "dir " << index << " has old filen: " <<
           std::setfill('0') << std::hex << std::uppercase << std::setw(8) <<
           sio->swap_filen);

    assert(slot->basics.swap_file_sz > 0);
    assert(slot->basics.swap_file_sz == e.swap_file_sz);

    sio->diskOffset = diskOffset(sio->swap_filen);
    assert(sio->diskOffset + sio->payloadEnd <= diskOffsetLimit());

    sio->file(theFile);
    return sio;
}

void
Rock::SwapDir::ioCompletedNotification()
{
    if (!theFile)
        fatalf("Rock cache_dir failed to initialize db file: %s", filePath);

    if (theFile->error())
        fatalf("Rock cache_dir at %s failed to open db file: %s", filePath,
               xstrerror());

    debugs(47, 2, "Rock cache_dir[" << index << "] limits: " <<
           std::setw(12) << maxSize() << " disk bytes and " <<
           std::setw(7) << map->entryLimit() << " entries");

    rebuild();
}

void
Rock::SwapDir::closeCompleted()
{
    theFile = NULL;
}

void
Rock::SwapDir::readCompleted(const char *buf, int rlen, int errflag, RefCount< ::ReadRequest> r)
{
    ReadRequest *request = dynamic_cast<Rock::ReadRequest*>(r.getRaw());
    assert(request);
    IoState::Pointer sio = request->sio;

    if (errflag == DISK_OK && rlen > 0)
        sio->offset_ += rlen;
    assert(sio->diskOffset + sio->offset_ <= diskOffsetLimit()); // post-factum

    StoreIOState::STRCB *callb = sio->read.callback;
    assert(callb);
    sio->read.callback = NULL;
    void *cbdata;
    if (cbdataReferenceValidDone(sio->read.callback_data, &cbdata))
        callb(cbdata, r->buf, rlen, sio.getRaw());
}

void
Rock::SwapDir::writeCompleted(int errflag, size_t rlen, RefCount< ::WriteRequest> r)
{
    Rock::WriteRequest *request = dynamic_cast<Rock::WriteRequest*>(r.getRaw());
    assert(request);
    assert(request->sio !=  NULL);
    IoState &sio = *request->sio;

    if (errflag == DISK_OK) {
        // close, assuming we only write once; the entry gets the read lock
        map->closeForWriting(sio.swap_filen, true);
        // do not increment sio.offset_ because we do it in sio->write()
    } else {
        // Do not abortWriting here. The entry should keep the write lock
        // instead of losing association with the store and confusing core.
        map->free(sio.swap_filen); // will mark as unusable, just in case
    }

    assert(sio.diskOffset + sio.offset_ <= diskOffsetLimit()); // post-factum

    sio.finishedWriting(errflag);
}

bool
Rock::SwapDir::full() const
{
    return map && map->full();
}

// storeSwapOutFileClosed calls this nethod on DISK_NO_SPACE_LEFT,
// but it should not happen for us
void
Rock::SwapDir::diskFull()
{
    debugs(20, DBG_IMPORTANT, "BUG: No space left with rock cache_dir: " <<
           filePath);
}

/// purge while full(); it should be sufficient to purge just one
void
Rock::SwapDir::maintain()
{
    debugs(47,3, HERE << "cache_dir[" << index << "] guards: " <<
           !repl << !map << !full() << StoreController::store_dirs_rebuilding);

    if (!repl)
        return; // no means (cannot find a victim)

    if (!map)
        return; // no victims (yet)

    if (!full())
        return; // no need (to find a victim)

    // XXX: UFSSwapDir::maintain says we must quit during rebuild
    if (StoreController::store_dirs_rebuilding)
        return;

    debugs(47,3, HERE << "cache_dir[" << index << "] state: " << map->full() <<
           ' ' << currentSize() << " < " << diskOffsetLimit());

    // Hopefully, we find a removable entry much sooner (TODO: use time?)
    const int maxProbed = 10000;
    RemovalPurgeWalker *walker = repl->PurgeInit(repl, maxProbed);

    // It really should not take that long, but this will stop "infinite" loops
    const int maxFreed = 1000;
    int freed = 0;
    // TODO: should we purge more than needed to minimize overheads?
    for (; freed < maxFreed && full(); ++freed) {
        if (StoreEntry *e = walker->Next(walker))
            e->release(); // will call our unlink() method
        else
            break; // no more objects
    }

    debugs(47,2, HERE << "Rock cache_dir[" << index << "] freed " << freed <<
           " scanned " << walker->scanned << '/' << walker->locked);

    walker->Done(walker);

    if (full()) {
        debugs(47, DBG_CRITICAL, "ERROR: Rock cache_dir[" << index << "] " <<
               "is still full after freeing " << freed << " entries. A bug?");
    }
}

void
Rock::SwapDir::reference(StoreEntry &e)
{
    debugs(47, 5, HERE << &e << ' ' << e.swap_dirn << ' ' << e.swap_filen);
    if (repl && repl->Referenced)
        repl->Referenced(repl, &e, &e.repl);
}

bool
Rock::SwapDir::dereference(StoreEntry &e, bool)
{
    debugs(47, 5, HERE << &e << ' ' << e.swap_dirn << ' ' << e.swap_filen);
    if (repl && repl->Dereferenced)
        repl->Dereferenced(repl, &e, &e.repl);

    // no need to keep e in the global store_table for us; we have our own map
    return false;
}

bool
Rock::SwapDir::unlinkdUseful() const
{
    // no entry-specific files to unlink
    return false;
}

void
Rock::SwapDir::unlink(StoreEntry &e)
{
    debugs(47, 5, HERE << e);
    ignoreReferences(e);
    map->free(e.swap_filen);
    disconnect(e);
}

void
Rock::SwapDir::trackReferences(StoreEntry &e)
{
    debugs(47, 5, HERE << e);
    if (repl)
        repl->Add(repl, &e, &e.repl);
}

void
Rock::SwapDir::ignoreReferences(StoreEntry &e)
{
    debugs(47, 5, HERE << e);
    if (repl)
        repl->Remove(repl, &e, &e.repl);
}

void
Rock::SwapDir::statfs(StoreEntry &e) const
{
    storeAppendPrintf(&e, "\n");
    storeAppendPrintf(&e, "Maximum Size: %" PRIu64 " KB\n", maxSize() >> 10);
    storeAppendPrintf(&e, "Current Size: %.2f KB %.2f%%\n",
                      currentSize() / 1024.0,
                      Math::doublePercent(currentSize(), maxSize()));

    if (map) {
        const int limit = map->entryLimit();
        storeAppendPrintf(&e, "Maximum entries: %9d\n", limit);
        if (limit > 0) {
            const int entryCount = map->entryCount();
            storeAppendPrintf(&e, "Current entries: %9d %.2f%%\n",
                              entryCount, (100.0 * entryCount / limit));

            if (limit < 100) { // XXX: otherwise too expensive to count
                Ipc::ReadWriteLockStats stats;
                map->updateStats(stats);
                stats.dump(e);
            }
        }
    }

    storeAppendPrintf(&e, "Pending operations: %d out of %d\n",
                      store_open_disk_fd, Config.max_open_disk_fds);

    storeAppendPrintf(&e, "Flags:");

    if (flags.selected)
        storeAppendPrintf(&e, " SELECTED");

    if (flags.read_only)
        storeAppendPrintf(&e, " READ-ONLY");

    storeAppendPrintf(&e, "\n");

}

namespace Rock
{
RunnerRegistrationEntry(rrAfterConfig, SwapDirRr);
}

void Rock::SwapDirRr::create(const RunnerRegistry &)
{
    Must(owners.empty());
    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        if (const Rock::SwapDir *const sd = dynamic_cast<Rock::SwapDir *>(INDEXSD(i))) {
            Rock::SwapDir::DirMap::Owner *const owner =
                Rock::SwapDir::DirMap::Init(sd->path, sd->entryLimitAllowed());
            owners.push_back(owner);
        }
    }
}

Rock::SwapDirRr::~SwapDirRr()
{
    for (size_t i = 0; i < owners.size(); ++i)
        delete owners[i];
}
