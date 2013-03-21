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

Rock::SwapDir::SwapDir(): ::SwapDir("rock"), 
    slotSize(HeaderSize), filePath(NULL), map(NULL), io(NULL),
    waitingForPage(NULL)
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
    const Ipc::StoreMapAnchor *const slot = map->openForReading(key, filen);
    if (!slot)
        return NULL;

    const Ipc::StoreMapAnchor::Basics &basics = slot->basics;

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
    const uint64_t spaceSize = !freeSlots ?
        maxSize() : (slotSize * freeSlots->size());
    // everything that is not free is in use
    return maxSize() - spaceSize;
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
    const int64_t eWanted = (maxSize() - HeaderSize)/slotSize;
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
        if (res != 0)
            createError("mkdir");
    }

    debugs (47, DBG_IMPORTANT, "Creating Rock db: " << filePath);
    const int swap = open(filePath, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0600);
    if (swap < 0)
        createError("create");

#if SLOWLY_FILL_WITH_ZEROS
    char block[1024];
    Must(maxSize() % sizeof(block) == 0);
    memset(block, '\0', sizeof(block));

    for (off_t offset = 0; offset < maxSize(); offset += sizeof(block)) {
        if (write(swap, block, sizeof(block)) != sizeof(block))
            createError("write");
    }
#else
    if (ftruncate(swap, maxSize()) != 0)
        createError("truncate");

    char header[HeaderSize];
    memset(header, '\0', sizeof(header));
    if (write(swap, header, sizeof(header)) != sizeof(header))
        createError("write");
#endif

    close(swap);
}

// report Rock DB creation error and exit
void
Rock::SwapDir::createError(const char *const msg) {
    debugs(47, DBG_CRITICAL, "ERROR: Failed to initialize Rock Store db in " <<
           filePath << "; " << msg << " error: " << xstrerror());
    fatal("Rock Store db creation error");
}

void
Rock::SwapDir::init()
{
    debugs(47,2, HERE);

    // XXX: SwapDirs aren't refcounted. We make IORequestor calls, which
    // are refcounted. We up our count once to avoid implicit delete's.
    lock();

    freeSlots = shm_old(Ipc::Mem::PageStack)(freeSlotsPath());

    Must(!map);
    map = new DirMap(inodeMapPath());
    map->cleaner = this;

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
    vector->options.push_back(new ConfigOptionAdapter<SwapDir>(*const_cast<SwapDir *>(this), &SwapDir::parseSizeOption, &SwapDir::dumpSizeOption));
    vector->options.push_back(new ConfigOptionAdapter<SwapDir>(*const_cast<SwapDir *>(this), &SwapDir::parseTimeOption, &SwapDir::dumpTimeOption));
    vector->options.push_back(new ConfigOptionAdapter<SwapDir>(*const_cast<SwapDir *>(this), &SwapDir::parseRateOption, &SwapDir::dumpRateOption));
    return vector;
}

bool
Rock::SwapDir::allowOptionReconfigure(const char *const option) const
{
    return strcmp(option, "slot-size") != 0 &&
           ::SwapDir::allowOptionReconfigure(option);
}

/// parses time-specific options; mimics ::SwapDir::optionObjectSizeParse()
bool
Rock::SwapDir::parseTimeOption(char const *option, const char *value, int reconfig)
{
    // TODO: ::SwapDir or, better, Config should provide time-parsing routines,
    // including time unit handling. Same for size and rate.

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

/// parses size-specific options; mimics ::SwapDir::optionObjectSizeParse()
bool
Rock::SwapDir::parseSizeOption(char const *option, const char *value, int reconfig)
{
    uint64_t *storedSize;
    if (strcmp(option, "slot-size") == 0)
        storedSize = &slotSize;
    else
        return false;

    if (!value)
        self_destruct();

    // TODO: handle size units and detect parsing errors better
    const uint64_t newSize = strtoll(value, NULL, 10);
    if (newSize <= 0) {
        debugs(3, DBG_CRITICAL, "FATAL: cache_dir " << path << ' ' << option << " must be positive; got: " << newSize);
        self_destruct();
    }

    if (newSize <= sizeof(DbCellHeader)) {
        debugs(3, DBG_CRITICAL, "FATAL: cache_dir " << path << ' ' << option << " must exceed " << sizeof(DbCellHeader) << "; got: " << newSize);
        self_destruct();
    }

    if (!reconfig)
        *storedSize = newSize;
    else if (*storedSize != newSize) {
        debugs(3, DBG_IMPORTANT, "WARNING: cache_dir " << path << ' ' << option
               << " cannot be changed dynamically, value left unchanged: " <<
               *storedSize);
    }

    return true;
}

/// reports size-specific options; mimics ::SwapDir::optionObjectSizeDump()
void
Rock::SwapDir::dumpSizeOption(StoreEntry * e) const
{
    storeAppendPrintf(e, " slot-size=%" PRId64, slotSize);
}

/// check the results of the configuration; only level-0 debugging works here
void
Rock::SwapDir::validateOptions()
{
    if (slotSize <= 0)
        fatal("Rock store requires a positive slot-size");

    const int64_t maxSizeRoundingWaste = 1024 * 1024; // size is configured in MB
    const int64_t slotSizeRoundingWaste = slotSize;
    const int64_t maxRoundingWaste =
        max(maxSizeRoundingWaste, slotSizeRoundingWaste);
    const int64_t usableDiskSize = diskOffset(entryLimitAllowed());
    const int64_t diskWasteSize = maxSize() - usableDiskSize;
    Must(diskWasteSize >= 0);

    // warn if maximum db size is not reachable due to sfileno limit
    if (entryLimitAllowed() == entryLimitHigh() &&
            diskWasteSize >= maxRoundingWaste) {
        debugs(47, DBG_CRITICAL, "Rock store cache_dir[" << index << "] '" << path << "':");
        debugs(47, DBG_CRITICAL, "\tmaximum number of entries: " << entryLimitAllowed());
        debugs(47, DBG_CRITICAL, "\tdb slot size: " << slotSize << " Bytes");
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

    sfileno filen;
    Ipc::StoreMapAnchor *const slot =
        map->openForWriting(reinterpret_cast<const cache_key *>(e.key), filen);
    if (!slot) {
        debugs(47, 5, HERE << "map->add failed");
        return NULL;
    }

    assert(filen >= 0);
    slot->set(e);

    // XXX: We rely on our caller, storeSwapOutStart(), to set e.fileno.
    // If that does not happen, the entry will not decrement the read level!

    Rock::SwapDir::Pointer self(this);
    IoState *sio = new IoState(self, &e, cbFile, cbIo, data);

    sio->swap_dirn = index;
    sio->swap_filen = filen;
    sio->writeableAnchor_ = slot;

    debugs(47,5, HERE << "dir " << index << " created new filen " <<
           std::setfill('0') << std::hex << std::uppercase << std::setw(8) <<
           sio->swap_filen << std::dec << " starting at " <<
           diskOffset(sio->swap_filen));

    sio->file(theFile);

    trackReferences(e);
    return sio;
}

int64_t
Rock::SwapDir::diskOffset(int filen) const
{
    assert(filen >= 0);
    return HeaderSize + slotSize*filen;
}

int64_t
Rock::SwapDir::diskOffset(Ipc::Mem::PageId &pageId) const
{
    assert(pageId);
    return diskOffset(pageId.number - 1);
}

int64_t
Rock::SwapDir::diskOffsetLimit() const
{
    assert(map);
    return diskOffset(map->entryLimit());
}

int
Rock::SwapDir::entryMaxPayloadSize() const
{
    return slotSize - sizeof(DbCellHeader);
}

int
Rock::SwapDir::entriesNeeded(const int64_t objSize) const
{
    return (objSize + entryMaxPayloadSize() - 1) / entryMaxPayloadSize();
}

bool
Rock::SwapDir::useFreeSlot(Ipc::Mem::PageId &pageId)
{
    if (freeSlots->pop(pageId)) {
        debugs(47, 5, "got a previously free slot: " << pageId);
        return true;
    }

    // catch free slots delivered to noteFreeMapSlice()
    assert(!waitingForPage);
    waitingForPage = &pageId;
    if (map->purgeOne()) {
        assert(!waitingForPage); // noteFreeMapSlice() should have cleared it
        assert(pageId.set());
        debugs(47, 5, "got a previously busy slot: " << pageId);
        return true;
    }
    assert(waitingForPage == &pageId);
    waitingForPage = NULL;

    debugs(47, 3, "cannot get a slot; entries: " << map->entryCount());
    return false;
}

bool
Rock::SwapDir::validSlotId(const SlotId slotId) const
{
    return 0 <= slotId && slotId < entryLimitAllowed();
}

void
Rock::SwapDir::noteFreeMapSlice(const sfileno sliceId)
{
    Ipc::Mem::PageId pageId;
    pageId.pool = index+1;
    pageId.number = sliceId+1;
    if (waitingForPage) {
        *waitingForPage = pageId;
        waitingForPage = NULL;
    } else {
        freeSlots->push(pageId);
    }
}

// tries to open an old entry with swap_filen for reading
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
    const Ipc::StoreMapAnchor *slot = map->peekAtReader(e.swap_filen);
    if (!slot)
        return NULL; // we were writing afterall

    Rock::SwapDir::Pointer self(this);
    IoState *sio = new IoState(self, &e, cbFile, cbIo, data);

    sio->swap_dirn = index;
    sio->swap_filen = e.swap_filen;
    sio->readableAnchor_ = slot;
    sio->file(theFile);

    debugs(47,5, HERE << "dir " << index << " has old filen: " <<
           std::setfill('0') << std::hex << std::uppercase << std::setw(8) <<
           sio->swap_filen);

    assert(slot->sameKey(static_cast<const cache_key*>(e.key)));
    assert(slot->basics.swap_file_sz > 0);
    assert(slot->basics.swap_file_sz == e.swap_file_sz);

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

    // quit if somebody called IoState::close() while we were waiting
    if (!sio.stillWaiting()) {
        debugs(79, 3, "ignoring closed entry " << sio.swap_filen);
        return;
    }

    if (errflag == DISK_OK) {
        // do not increment sio.offset_ because we do it in sio->write()
        if (request->isLast) {
            // close, the entry gets the read lock
            map->closeForWriting(sio.swap_filen, true);
            sio.finishedWriting(errflag);
        }
    } else {
        writeError(sio.swap_filen);
        sio.finishedWriting(errflag);
        // and hope that Core will call disconnect() to close the map entry
    }
}

void
Rock::SwapDir::writeError(const sfileno fileno)
{
    // Do not abortWriting here. The entry should keep the write lock
    // instead of losing association with the store and confusing core.
    map->freeEntry(fileno); // will mark as unusable, just in case
    // All callers must also call IoState callback, to propagate the error.
}

bool
Rock::SwapDir::full() const
{
    return freeSlots != NULL && !freeSlots->size();
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
    // The Store calls this to free some db space, but there is nothing wrong
    // with a full() db, except when db has to shrink after reconfigure, and
    // we do not support shrinking yet (it would have to purge specific slots).
    // TODO: Disable maintain() requests when they are pointless.
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
    map->freeEntry(e.swap_filen);
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

            const unsigned int slotsFree = !freeSlots ? 0 : freeSlots->size();
            if (slotsFree <= static_cast<const unsigned int>(limit)) {
                const int usedSlots = limit - static_cast<const int>(slotsFree);
                storeAppendPrintf(&e, "Used slots:      %9d %.2f%%\n",
                                  usedSlots, (100.0 * usedSlots / limit));
            }
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

const char *
Rock::SwapDir::inodeMapPath() const {
    static String inodesPath;
    inodesPath = path;
    inodesPath.append("_inodes");
    return inodesPath.termedBuf();
}

const char *
Rock::SwapDir::freeSlotsPath() const {
    static String spacesPath;
    spacesPath = path;
    spacesPath.append("_spaces");
    return spacesPath.termedBuf();
}

namespace Rock
{
RunnerRegistrationEntry(rrAfterConfig, SwapDirRr);
}

void Rock::SwapDirRr::create(const RunnerRegistry &)
{
    Must(mapOwners.empty() && freeSlotsOwners.empty());
    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        if (const Rock::SwapDir *const sd = dynamic_cast<Rock::SwapDir *>(INDEXSD(i))) {
            const int64_t capacity = sd->entryLimitAllowed();

            SwapDir::DirMap::Owner *const mapOwner =
                SwapDir::DirMap::Init(sd->inodeMapPath(), capacity);
            mapOwners.push_back(mapOwner);

            // XXX: remove pool id and counters from PageStack
            Ipc::Mem::Owner<Ipc::Mem::PageStack> *const freeSlotsOwner =
                shm_new(Ipc::Mem::PageStack)(sd->freeSlotsPath(),
                                             i+1, capacity,
                                             sizeof(DbCellHeader));
            freeSlotsOwners.push_back(freeSlotsOwner);

            // XXX: add method to initialize PageStack with no free pages
            while (true) {
                Ipc::Mem::PageId pageId;
                if (!freeSlotsOwner->object()->pop(pageId))
                    break;
            }
        }
    }
}

Rock::SwapDirRr::~SwapDirRr()
{
    for (size_t i = 0; i < mapOwners.size(); ++i) {
        delete mapOwners[i];
        delete freeSlotsOwners[i];
    }
}
