/*
 * $Id$
 *
 * DEBUG: section 47    Store Directory Routines
 */

#include "config.h"
#include "Parsing.h"
#include <iomanip>
#include "MemObject.h"
#include "DiskIO/DiskIOModule.h"
#include "DiskIO/DiskIOStrategy.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
#include "fs/rock/RockSwapDir.h"
#include "fs/rock/RockIoState.h"
#include "fs/rock/RockIoRequests.h"
#include "fs/rock/RockRebuild.h"

// must be divisible by 1024 due to cur_size and max_size KB madness
const int64_t Rock::SwapDir::HeaderSize = 16*1024;

Rock::SwapDir::SwapDir(): ::SwapDir("rock"), filePath(NULL), io(NULL)
{
}

Rock::SwapDir::~SwapDir()
{
    delete io;
    safe_free(filePath);
}

StoreSearch *
Rock::SwapDir::search(String const url, HttpRequest *)
{
    assert(false); return NULL; // XXX: implement
}

// TODO: encapsulate as a tool; identical to CossSwapDir::create()
void
Rock::SwapDir::create()
{
    assert(path);
    assert(filePath);

    debugs (47,3, HERE << "creating in " << path);

    struct stat swap_sb;
    if (::stat(path, &swap_sb) < 0) {
        debugs (47, 1, "Creating Rock db directory: " << path);
#ifdef _SQUID_MSWIN_
        const int res = mkdir(path);
#else
        const int res = mkdir(path, 0700);
#endif
        if (res != 0) {
            debugs(47,0, "Failed to create Rock db dir " << path <<
                ": " << xstrerror());
            fatal("Rock Store db creation error");
		}
	}

#if SLOWLY_FILL_WITH_ZEROS
    /* TODO just set the file size */
    char block[1024]; // max_size is in KB so this is one unit of max_size
    memset(block, '\0', sizeof(block));

    const int swap = open(filePath, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0600);
    for (off_t offset = 0; offset < max_size; ++offset) {
        if (write(swap, block, sizeof(block)) != sizeof(block)) {
            debugs(47,0, "Failed to create Rock Store db in " << filePath <<
                ": " << xstrerror());
            fatal("Rock Store db creation error");
		}
	}
    close(swap);
#else
    const int swap = open(filePath, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0600);
    if (swap < 0) {
        debugs(47,0, "Failed to initialize Rock Store db in " << filePath <<
            "; create error: " << xstrerror());
        fatal("Rock Store db creation error");
    }

    if (ftruncate(swap, maximumSize()) != 0) {
        debugs(47,0, "Failed to initialize Rock Store db in " << filePath <<
            "; truncate error: " << xstrerror());
        fatal("Rock Store db creation error");
    }

    char header[HeaderSize];
    memset(header, '\0', sizeof(header));
    if (write(swap, header, sizeof(header)) != sizeof(header)) {
        debugs(47,0, "Failed to initialize Rock Store db in " << filePath <<
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
    RefCountReference();

    DiskIOModule *m = DiskIOModule::Find("Mmapped"); // TODO: configurable?
    assert(m);
    io = m->createStrategy();
    io->init();

    theFile = io->newFile(filePath);
    theFile->open(O_RDWR, 0644, this);

    rebuild();
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

    parseSize();
    parseOptions(0);

    repl = createRemovalPolicy(Config.replPolicy);

    validateOptions();
}

void
Rock::SwapDir::reconfigure(int, char *)
{
    parseSize();
    parseOptions(1);
    // TODO: can we reconfigure the replacement policy (repl)?
    validateOptions();
}

/// parse maximum db disk size
void
Rock::SwapDir::parseSize()
{
    max_size = GetInteger() << 10; // MBytes to KBytes
    if (max_size < 0)
        fatal("negative Rock cache_dir size value");
}

/// check the results of the configuration; only level-0 debugging works here
void
Rock::SwapDir::validateOptions()
{
    if (max_objsize <= 0)
        fatal("Rock store requires a positive max-size");

    const int64_t eLimitHi = 0xFFFFFF; // Core sfileno maximum
    const int64_t eLimitLo = map.entryLimit(); // dynamic shrinking unsupported
    const int64_t eWanted = (maximumSize() - HeaderSize)/max_objsize;
    const int64_t eAllowed = min(max(eLimitLo, eWanted), eLimitHi);

    map.resize(eAllowed); // the map may decide to use an even lower limit

    // Note: We could try to shrink max_size now. It is stored in KB so we
    // may not be able to make it match the end of the last entry exactly.
    const int64_t mapRoundWasteMx = max_objsize*sizeof(long)*8;
    const int64_t sizeRoundWasteMx = 1024; // max_size stored in KB
    const int64_t roundingWasteMx = max(mapRoundWasteMx, sizeRoundWasteMx);
    const int64_t totalWaste = maximumSize() - diskOffsetLimit();
    assert(diskOffsetLimit() <= maximumSize());

    // warn if maximum db size is not reachable due to sfileno limit
    if (map.entryLimit() == map.AbsoluteEntryLimit() &&
        totalWaste > roundingWasteMx) {
        debugs(47, 0, "Rock store cache_dir[" << index << "]:");
        debugs(47, 0, "\tmaximum number of entries: " << map.entryLimit());
        debugs(47, 0, "\tmaximum entry size: " << max_objsize << " bytes");
        debugs(47, 0, "\tmaximum db size: " << maximumSize() << " bytes");
        debugs(47, 0, "\tusable db size:  " << diskOffsetLimit() << " bytes");
        debugs(47, 0, "\tdisk space waste: " << totalWaste << " bytes");
        debugs(47, 0, "WARNING: Rock store config wastes space.");
	}

    if (!repl) {
        debugs(47,0, "ERROR: Rock cache_dir[" << index << "] " <<
            "lacks replacement policy and will overflow.");
        // not fatal because it can be added later
	}

    cur_size = (HeaderSize + max_objsize * map.entryCount()) >> 10;
}

void
Rock::SwapDir::rebuild() {
    ++StoreController::store_dirs_rebuilding;
    Rebuild *r = new Rebuild(this);
    r->start(); // will delete self when done
}

/* Add a new object to the cache with empty memory copy and pointer to disk
 * use to rebuild store from disk. XXX: dupes UFSSwapDir::addDiskRestore */
StoreEntry *
Rock::SwapDir::addEntry(int fileno, const StoreEntry &from)
{
    /* if you call this you'd better be sure file_number is not
     * already in use! */
    StoreEntry *e = new StoreEntry(); // TODO: optimize by reusing "from"?
    debugs(47, 5, HERE << e << ' ' << storeKeyText((const cache_key*)from.key)
       << ", fileno="<< std::setfill('0') << std::hex << std::uppercase <<
       std::setw(8) << fileno);
    e->store_status = STORE_OK;
    e->setMemStatus(NOT_IN_MEMORY);
    e->swap_status = SWAPOUT_DONE;
    e->swap_filen = fileno;
    e->swap_dirn = index;
    e->swap_file_sz = from.swap_file_sz;
    e->lock_count = 0;
    e->lastref = from.lastref;
    e->timestamp = from.timestamp;
    e->expires = from.expires;
    e->lastmod = from.lastmod;
    e->refcount = from.refcount;
    e->flags = from.flags;
    EBIT_SET(e->flags, ENTRY_CACHABLE);
    EBIT_CLR(e->flags, RELEASE_REQUEST);
    EBIT_CLR(e->flags, KEY_PRIVATE);
    e->ping_status = PING_NONE;
    EBIT_CLR(e->flags, ENTRY_VALIDATED);
    map.use(e->swap_filen);
    e->hashInsert((const cache_key*)from.key); /* do it after we clear KEY_PRIVATE */
    trackReferences(*e);
    return e;
}


int
Rock::SwapDir::canStore(const StoreEntry &e) const
{
    debugs(47,8, HERE << e.swap_file_sz << " ? " << max_objsize);

    if (EBIT_TEST(e.flags, ENTRY_SPECIAL))
        return -1;

    if (io->shedLoad())
        return -1;

    return io->load();
}

StoreIOState::Pointer
Rock::SwapDir::createStoreIO(StoreEntry &e, StoreIOState::STFNCB *cbFile, StoreIOState::STIOCB *cbIo, void *data)
{
    if (!theFile || theFile->error()) {
        debugs(47,4, HERE << theFile);
        return NULL;
    }

    if (full()) {
        maintain();
        if (full()) // maintain() above warns when it fails
            return NULL;
    }

    IoState *sio = new IoState(this, &e, cbFile, cbIo, data);

    sio->swap_dirn = index;
    sio->swap_filen = map.useNext();
    sio->offset_ = diskOffset(sio->swap_filen);
    sio->entrySize = e.objectLen() + e.mem_obj->swap_hdr_sz;

    debugs(47,5, HERE << "dir " << index << " created new fileno " <<
        std::setfill('0') << std::hex << std::uppercase << std::setw(8) <<
        sio->swap_filen << std::dec << " at " << sio->offset_ << " size: " <<
        sio->entrySize << " (" << e.objectLen() << '+' <<
        e.mem_obj->swap_hdr_sz << ")");

    assert(sio->offset_ + sio->entrySize <= diskOffsetLimit());

    sio->file(theFile);

    trackReferences(e);
    return sio;
}

int64_t
Rock::SwapDir::diskOffset(int filen) const
{
    return HeaderSize + max_objsize*filen;
}

int64_t
Rock::SwapDir::diskOffsetLimit() const
{
    return diskOffset(map.entryLimit());
}

StoreIOState::Pointer
Rock::SwapDir::openStoreIO(StoreEntry &e, StoreIOState::STFNCB *cbFile, StoreIOState::STIOCB *cbIo, void *data)
{
    if (!theFile || theFile->error()) {
        debugs(47,4, HERE << theFile);
        return NULL;
    }

    IoState *sio = new IoState(this, &e, cbFile, cbIo, data);

    sio->swap_dirn = index;
    sio->swap_filen = e.swap_filen;
    debugs(47,5, HERE << "dir " << index << " has old fileno: " <<
        std::setfill('0') << std::hex << std::uppercase << std::setw(8) <<
        sio->swap_filen);

    assert(map.valid(sio->swap_filen));
    sio->offset_ = diskOffset(sio->swap_filen);
    sio->entrySize = e.swap_file_sz;
    assert(sio->entrySize <= max_objsize);

    if (!map.has(sio->swap_filen)) {
        debugs(47,1, HERE << "bug: dir " << index << " lost fileno: " <<
            std::setfill('0') << std::hex << std::uppercase << std::setw(8) <<
            sio->swap_filen);
        return NULL;
    }

    assert(sio->offset_ + sio->entrySize <= diskOffsetLimit());

    sio->file(theFile);
    return sio;
}

void
Rock::SwapDir::ioCompletedNotification()
{
    if (!theFile) {
        debugs(47, 1, HERE << filePath << ": initialization failure or " <<
            "premature close of rock db file");
        fatalf("Rock cache_dir failed to initialize db file: %s", filePath);
    }

    if (theFile->error()) {
        debugs(47, 1, HERE << filePath << ": " << xstrerror());
        fatalf("Rock cache_dir failed to open db file: %s", filePath);
	}

    cur_size = (HeaderSize + max_objsize * map.entryCount()) >> 10;

    // TODO: lower debugging level
    debugs(47,1, "Rock cache_dir[" << index << "] limits: " << 
        std::setw(12) << maximumSize() << " disk bytes and " <<
        std::setw(7) << map.entryLimit() << " entries");
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

    // do not increment sio->offset_: callers always supply relative offset

    StoreIOState::STRCB *callback = sio->read.callback;
    assert(callback);
    sio->read.callback = NULL;
    void *cbdata;
    if (cbdataReferenceValidDone(sio->read.callback_data, &cbdata))
        callback(cbdata, r->buf, rlen, sio.getRaw());
}

void
Rock::SwapDir::writeCompleted(int errflag, size_t rlen, RefCount< ::WriteRequest> r)
{
    Rock::WriteRequest *request = dynamic_cast<Rock::WriteRequest*>(r.getRaw());
    assert(request);
    assert(request->sio !=  NULL);
    IoState &sio = *request->sio;
    if (errflag != DISK_OK)
        map.clear(sio.swap_filen); // TODO: test by forcing failure
    // else sio.offset_ += rlen;

    // TODO: always compute cur_size based on map, do not store it
    cur_size = (HeaderSize + max_objsize * map.entryCount()) >> 10;
    assert(sio.offset_ <= diskOffsetLimit()); // post-factum check

    sio.finishedWriting(errflag);
}

bool
Rock::SwapDir::full() const
{
    return map.full();
}

void
Rock::SwapDir::updateSize(int64_t size, int sign)
{
    // it is not clear what store_swap_size really is; TODO: move low-level
	// size maintenance to individual store dir types
    cur_size = (HeaderSize + max_objsize * map.entryCount()) >> 10;
    store_swap_size = cur_size;

    if (sign > 0)
        ++n_disk_objects;
    else if (sign < 0)
        --n_disk_objects;
}

// storeSwapOutFileClosed calls this nethod on DISK_NO_SPACE_LEFT,
// but it should not happen for us
void
Rock::SwapDir::diskFull() {
    debugs(20,1, "Internal ERROR: No space left error with rock cache_dir: " <<
        filePath);
}

/// purge while full(); it should be sufficient to purge just one
void
Rock::SwapDir::maintain()
{
    debugs(47,3, HERE << "cache_dir[" << index << "] guards: " << 
        StoreController::store_dirs_rebuilding << !repl << !full());

    // XXX: UFSSwapDir::maintain says we must quit during rebuild
    if (StoreController::store_dirs_rebuilding)
        return;

    if (!repl)
        return; // no means (cannot find a victim)

    if (!full())
        return; // no need (to find a victim)

    debugs(47,3, HERE << "cache_dir[" << index << "] state: " << 
        map.full() << ' ' << currentSize() << " < " << diskOffsetLimit());

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
        debugs(47,0, "ERROR: Rock cache_dir[" << index << "] " <<
            "is still full after freeing " << freed << " entries. A bug?");
	}
}

void
Rock::SwapDir::reference(StoreEntry &e)
{
    debugs(47, 5, HERE << &e << ' ' << e.swap_dirn << ' ' << e.swap_filen);
    if (repl->Referenced)
        repl->Referenced(repl, &e, &e.repl);
}

void
Rock::SwapDir::dereference(StoreEntry &e)
{
    debugs(47, 5, HERE << &e << ' ' << e.swap_dirn << ' ' << e.swap_filen);
    if (repl->Dereferenced)
        repl->Dereferenced(repl, &e, &e.repl);
}

void
Rock::SwapDir::unlink(int fileno)
{
    debugs(47,5, HERE << index << ' ' << fileno);
    if (map.has(fileno)) {
        map.clear(fileno);
        cur_size = (HeaderSize + max_objsize * map.entryCount()) >> 10;
        // XXX: update store
	}
}

void
Rock::SwapDir::unlink(StoreEntry &e)
{
    debugs(47, 5, HERE << &e << ' ' << e.swap_dirn << ' ' << e.swap_filen);
    ignoreReferences(e);
    unlink(e.swap_filen);
}

void
Rock::SwapDir::trackReferences(StoreEntry &e)
{
    debugs(47, 5, HERE << &e << ' ' << e.swap_dirn << ' ' << e.swap_filen);
    repl->Add(repl, &e, &e.repl);
}


void
Rock::SwapDir::ignoreReferences(StoreEntry &e)
{
    debugs(47, 5, HERE << &e << ' ' << e.swap_dirn << ' ' << e.swap_filen);
    repl->Remove(repl, &e, &e.repl);
}

void
Rock::SwapDir::statfs(StoreEntry &e) const
{
    storeAppendPrintf(&e, "\n");
    storeAppendPrintf(&e, "Maximum Size: %"PRIu64" KB\n", max_size);
    storeAppendPrintf(&e, "Current Size: %"PRIu64" KB %.2f%%\n", cur_size,
                      100.0 * cur_size / max_size);

    storeAppendPrintf(&e, "Maximum entries: %9d\n", map.entryLimit());
    storeAppendPrintf(&e, "Current entries: %9d %.2f%%\n",
        map.entryCount(), (100.0 * map.entryCount() / map.entryLimit()));

    storeAppendPrintf(&e, "Pending operations: %d out of %d\n",
        store_open_disk_fd, Config.max_open_disk_fds);

    storeAppendPrintf(&e, "Flags:");

    if (flags.selected)
        storeAppendPrintf(&e, " SELECTED");

    if (flags.read_only)
        storeAppendPrintf(&e, " READ-ONLY");

    storeAppendPrintf(&e, "\n");

}
