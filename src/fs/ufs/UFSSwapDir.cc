/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 47    Store Directory Routines */

#define CLEAN_BUF_SZ 16384

#include "squid.h"
#include "cache_cf.h"
#include "ConfigOption.h"
#include "DiskIO/DiskIOModule.h"
#include "DiskIO/DiskIOStrategy.h"
#include "fde.h"
#include "FileMap.h"
#include "fs_io.h"
#include "globals.h"
#include "Parsing.h"
#include "RebuildState.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "store_key_md5.h"
#include "StoreSearchUFS.h"
#include "StoreSwapLogData.h"
#include "tools.h"
#include "UFSSwapDir.h"

#include <cerrno>
#include <cmath>
#include <random>
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

int Fs::Ufs::UFSSwapDir::NumberOfUFSDirs = 0;
int *Fs::Ufs::UFSSwapDir::UFSDirToGlobalDirMapping = NULL;

class UFSCleanLog : public SwapDir::CleanLog
{

public:
    UFSCleanLog(SwapDir *aSwapDir) : sd(aSwapDir) {}

    /// Get the next entry that is a candidate for clean log writing
    virtual const StoreEntry *nextEntry();

    /// "write" an entry to the clean log file.
    virtual void write(StoreEntry const &);

    SBuf cur;
    SBuf newLog;
    SBuf cln;
    char *outbuf = nullptr;
    off_t outbuf_offset = 0;
    int fd = -1;
    RemovalPolicyWalker *walker = nullptr;
    SwapDir *sd = nullptr;
};

const StoreEntry *
UFSCleanLog::nextEntry()
{
    const StoreEntry *entry = NULL;

    if (walker)
        entry = walker->Next(walker);

    return entry;
}

void
UFSCleanLog::write(StoreEntry const &e)
{
    StoreSwapLogData s;
    static size_t ss = sizeof(StoreSwapLogData);
    s.op = (char) SWAP_LOG_ADD;
    s.swap_filen = e.swap_filen;
    s.timestamp = e.timestamp;
    s.lastref = e.lastref;
    s.expires = e.expires;
    s.lastmod = e.lastModified();
    s.swap_file_sz = e.swap_file_sz;
    s.refcount = e.refcount;
    s.flags = e.flags;
    memcpy(&s.key, e.key, SQUID_MD5_DIGEST_LENGTH);
    s.finalize();
    memcpy(outbuf + outbuf_offset, &s, ss);
    outbuf_offset += ss;
    /* buffered write */

    if (outbuf_offset + ss >= CLEAN_BUF_SZ) {
        if (FD_WRITE_METHOD(fd, outbuf, outbuf_offset) < 0) {
            int xerrno = errno;
            /* XXX This error handling should probably move up to the caller */
            debugs(50, DBG_CRITICAL, MYNAME << newLog << ": write: " << xstrerr(xerrno));
            debugs(50, DBG_CRITICAL, MYNAME << "Current swap logfile not replaced.");
            file_close(fd);
            fd = -1;
            unlink(newLog.c_str());
            sd->cleanLog = NULL;
            delete this;
            return;
        }

        outbuf_offset = 0;
    }
}

bool
Fs::Ufs::UFSSwapDir::canStore(const StoreEntry &e, int64_t diskSpaceNeeded, int &load) const
{
    if (!SwapDir::canStore(e, diskSpaceNeeded, load))
        return false;

    if (IO->shedLoad())
        return false;

    load = IO->load();
    return true;
}

static void
FreeObject(void *address)
{
    StoreSwapLogData *anObject = static_cast <StoreSwapLogData *>(address);
    delete anObject;
}

static int
rev_int_sort(const void *A, const void *B)
{
    const int *i1 = (const int *)A;
    const int *i2 = (const int *)B;
    return *i2 - *i1;
}

void
Fs::Ufs::UFSSwapDir::parseSizeL1L2()
{
    int i = GetInteger();
    if (i <= 0)
        fatal("UFSSwapDir::parseSizeL1L2: invalid size value");

    const uint64_t size = static_cast<uint64_t>(i) << 20; // MBytes to Bytes

    /* just reconfigure it */
    if (reconfiguring) {
        if (size == maxSize())
            debugs(3, 2, "Cache dir '" << path << "' size remains unchanged at " << i << " MB");
        else
            debugs(3, DBG_IMPORTANT, "Cache dir '" << path << "' size changed to " << i << " MB");
    }

    max_size = size;

    l1 = GetInteger();

    if (l1 <= 0)
        fatal("UFSSwapDir::parseSizeL1L2: invalid level 1 directories value");

    l2 = GetInteger();

    if (l2 <= 0)
        fatal("UFSSwapDir::parseSizeL1L2: invalid level 2 directories value");
}

void
Fs::Ufs::UFSSwapDir::reconfigure()
{
    parseSizeL1L2();
    parseOptions(1);
}

void
Fs::Ufs::UFSSwapDir::parse (int anIndex, char *aPath)
{
    index = anIndex;
    path = xstrdup(aPath);

    parseSizeL1L2();

    /* Initialise replacement policy stuff */
    repl = createRemovalPolicy(Config.replPolicy);

    parseOptions(0);
}

void
Fs::Ufs::UFSSwapDir::changeIO(DiskIOModule *module)
{
    DiskIOStrategy *anIO = module->createStrategy();
    safe_free(ioType);
    ioType = xstrdup(module->type());

    delete IO->io;
    IO->io = anIO;
    /* Change the IO Options */

    if (currentIOOptions && currentIOOptions->options.size() > 2) {
        delete currentIOOptions->options.back();
        currentIOOptions->options.pop_back();
    }

    /* TODO: factor out these 4 lines */
    ConfigOption *ioOptions = IO->io->getOptionTree();

    if (currentIOOptions && ioOptions)
        currentIOOptions->options.push_back(ioOptions);
}

bool
Fs::Ufs::UFSSwapDir::optionIOParse(char const *option, const char *value, int isaReconfig)
{
    if (strcmp(option, "IOEngine") != 0)
        return false;

    if (isaReconfig)
        /* silently ignore this */
        return true;

    if (!value) {
        self_destruct();
        return false;
    }

    DiskIOModule *module = DiskIOModule::Find(value);

    if (!module) {
        self_destruct();
        return false;
    }

    changeIO(module);

    return true;
}

void
Fs::Ufs::UFSSwapDir::optionIODump(StoreEntry * e) const
{
    storeAppendPrintf(e, " IOEngine=%s", ioType);
}

ConfigOption *
Fs::Ufs::UFSSwapDir::getOptionTree() const
{
    ConfigOption *parentResult = SwapDir::getOptionTree();

    if (currentIOOptions == NULL)
        currentIOOptions = new ConfigOptionVector();

    currentIOOptions->options.push_back(parentResult);

    currentIOOptions->options.push_back(new ConfigOptionAdapter<UFSSwapDir>(*const_cast<UFSSwapDir *>(this), &UFSSwapDir::optionIOParse, &UFSSwapDir::optionIODump));

    if (ConfigOption *ioOptions = IO->io->getOptionTree())
        currentIOOptions->options.push_back(ioOptions);

    ConfigOption* result = currentIOOptions;

    currentIOOptions = NULL;

    return result;
}

void
Fs::Ufs::UFSSwapDir::init()
{
    debugs(47, 3, HERE << "Initialising UFS SwapDir engine.");
    /* Parsing must be finished by now - force to NULL, don't delete */
    currentIOOptions = NULL;
    static int started_clean_event = 0;
    static const char *errmsg =
        "\tFailed to verify one of the swap directories, Check cache.log\n"
        "\tfor details.  Run 'squid -z' to create swap directories\n"
        "\tif needed, or if running Squid for the first time.";
    IO->init();

    if (verifyCacheDirs())
        fatal(errmsg);

    openLog();

    rebuild();

    if (!started_clean_event) {
        eventAdd("UFS storeDirClean", CleanEvent, NULL, 15.0, 1);
        started_clean_event = 1;
    }

    (void) fsBlockSize(path, &fs.blksize);
}

void
Fs::Ufs::UFSSwapDir::create()
{
    debugs(47, 3, "Creating swap space in " << path);
    createDirectory(path, 0);
    createSwapSubDirs();
}

Fs::Ufs::UFSSwapDir::UFSSwapDir(char const *aType, const char *anIOType) :
    SwapDir(aType),
    IO(NULL),
    fsdata(NULL),
    map(new FileMap()),
    suggest(0),
    l1(16),
    l2(256),
    swaplog_fd(-1),
    currentIOOptions(new ConfigOptionVector()),
    ioType(xstrdup(anIOType)),
    cur_size(0),
    n_disk_objects(0),
    rebuilding_(false)
{
    /* modulename is only set to disk modules that are built, by configure,
     * so the Find call should never return NULL here.
     */
    IO = new Fs::Ufs::UFSStrategy(DiskIOModule::Find(anIOType)->createStrategy());
}

Fs::Ufs::UFSSwapDir::~UFSSwapDir()
{
    if (swaplog_fd > -1) {
        file_close(swaplog_fd);
        swaplog_fd = -1;
    }
    xfree(ioType);
    delete map;
    delete IO;
    delete currentIOOptions;
}

void
Fs::Ufs::UFSSwapDir::dumpEntry(StoreEntry &e) const
{
    debugs(47, DBG_CRITICAL, HERE << "FILENO "<< std::setfill('0') << std::hex << std::uppercase << std::setw(8) << e.swap_filen);
    debugs(47, DBG_CRITICAL, HERE << "PATH " << fullPath(e.swap_filen, NULL)   );
    e.dump(0);
}

bool
Fs::Ufs::UFSSwapDir::doubleCheck(StoreEntry & e)
{

    struct stat sb;

    if (::stat(fullPath(e.swap_filen, NULL), &sb) < 0) {
        debugs(47, DBG_CRITICAL, HERE << "WARNING: Missing swap file");
        dumpEntry(e);
        return true;
    }

    if ((off_t)e.swap_file_sz != sb.st_size) {
        debugs(47, DBG_CRITICAL, HERE << "WARNING: Size Mismatch. Entry size: "
               << e.swap_file_sz << ", file size: " << sb.st_size);
        dumpEntry(e);
        return true;
    }

    return false;
}

void
Fs::Ufs::UFSSwapDir::statfs(StoreEntry & sentry) const
{
    int totl_kb = 0;
    int free_kb = 0;
    int totl_in = 0;
    int free_in = 0;
    int x;
    storeAppendPrintf(&sentry, "First level subdirectories: %d\n", l1);
    storeAppendPrintf(&sentry, "Second level subdirectories: %d\n", l2);
    storeAppendPrintf(&sentry, "Maximum Size: %" PRIu64 " KB\n", maxSize() >> 10);
    storeAppendPrintf(&sentry, "Current Size: %.2f KB\n", currentSize() / 1024.0);
    storeAppendPrintf(&sentry, "Percent Used: %0.2f%%\n",
                      Math::doublePercent(currentSize(), maxSize()));
    storeAppendPrintf(&sentry, "Filemap bits in use: %d of %d (%d%%)\n",
                      map->numFilesInMap(), map->capacity(),
                      Math::intPercent(map->numFilesInMap(), map->capacity()));
    x = fsStats(path, &totl_kb, &free_kb, &totl_in, &free_in);

    if (0 == x) {
        storeAppendPrintf(&sentry, "Filesystem Space in use: %d/%d KB (%d%%)\n",
                          totl_kb - free_kb,
                          totl_kb,
                          Math::intPercent(totl_kb - free_kb, totl_kb));
        storeAppendPrintf(&sentry, "Filesystem Inodes in use: %d/%d (%d%%)\n",
                          totl_in - free_in,
                          totl_in,
                          Math::intPercent(totl_in - free_in, totl_in));
    }

    storeAppendPrintf(&sentry, "Flags:");

    if (flags.selected)
        storeAppendPrintf(&sentry, " SELECTED");

    if (flags.read_only)
        storeAppendPrintf(&sentry, " READ-ONLY");

    storeAppendPrintf(&sentry, "\n");

    IO->statfs(sentry);
}

void
Fs::Ufs::UFSSwapDir::maintain()
{
    /* TODO: possible options for improvement;
     *
     * Note that too much aggression here is not good. It means that disk
     * controller is getting a long queue of removals to act on, along
     * with its regular I/O queue, and that client traffic is 'paused'
     * and growing the network I/O queue as well while the scan happens.
     * Possibly bad knock-on effects as Squid catches up on all that.
     *
     * Bug 2448 may have been a sign of what can wrong. At the least it
     * provides a test case for aggression effects in overflow conditions.
     *
     * - base removal limit on space saved, instead of count ?
     *
     * - base removal rate on a traffic speed counter ?
     *   as the purge took up more time out of the second it would grow to
     *   a graceful full pause
     *
     * - pass out a value to cause another event to be scheduled immediately
     *   instead of waiting a whole second more ?
     *   knock on; schedule less if all caches are under low-water
     *
     * - admin configurable removal rate or count ?
     *   the current numbers are arbitrary, config helps with experimental
     *   trials and future-proofing the install base.
     *   we also have this indirectly by shifting the relative positions
     *   of low-, high- water and the total capacity limit.
     */

    // minSize() is swap_low_watermark in bytes
    const uint64_t lowWaterSz = minSize();

    if (currentSize() < lowWaterSz) {
        debugs(47, 5, "space still available in " << path);
        return;
    }

    /* We can't delete objects while rebuilding swap */
    /* XXX each store should start maintaining as it comes online. */
    if (StoreController::store_dirs_rebuilding) {
        // suppress the warnings, except once each minute
        static int64_t lastWarn = 0;
        int warnLevel = 3;
        if (lastWarn+60 < squid_curtime) {
            lastWarn = squid_curtime;
            warnLevel = DBG_IMPORTANT;
        }
        debugs(47, warnLevel, StoreController::store_dirs_rebuilding << " cache_dir still rebuilding. Skip GC for " << path);
        return;
    }

    // maxSize() is cache_dir total size in bytes
    const uint64_t highWaterSz = ((maxSize() * Config.Swap.highWaterMark) / 100);

    // f is percentage of 'gap' filled between low- and high-water.
    // Used to reduced purge rate when between water markers, and
    // to multiply it more agressively the further above high-water
    // it reaches. But in a graceful linear growth curve.
    double f = 1.0;
    if (highWaterSz > lowWaterSz) {
        // might be equal. n/0 is bad.
        f = (double) (currentSize() - lowWaterSz) / (highWaterSz - lowWaterSz);
    }

    // how deep to look for a single object that can be removed
    int max_scan = (int) (f * 400.0 + 100.0);

    // try to purge only this many objects this cycle.
    int max_remove = (int) (f * 300.0 + 20.0);

    /*
     * This is kinda cheap, but so we need this priority hack?
     */
    debugs(47, 3, "f=" << f << ", max_scan=" << max_scan << ", max_remove=" << max_remove);

    RemovalPurgeWalker *walker = repl->PurgeInit(repl, max_scan);

    int removed = 0;
    // only purge while above low-water
    while (currentSize() >= lowWaterSz) {

        // stop if we reached max removals for this cycle,
        // Bug 2448 may be from this not clearing enough,
        // but it predates the current algorithm so not sure
        if (removed >= max_remove)
            break;

        StoreEntry *e = walker->Next(walker);

        // stop if all objects are locked / in-use,
        // or the cache is empty
        if (!e)
            break;      /* no more objects */

        ++removed;

        e->release(true);
    }

    walker->Done(walker);
    debugs(47, (removed ? 2 : 3), path <<
           " removed " << removed << "/" << max_remove << " f=" <<
           std::setprecision(4) << f << " max_scan=" << max_scan);

    // what if cache is still over the high watermark ?
    // Store::Maintain() schedules another purge in 1 second.
}

void
Fs::Ufs::UFSSwapDir::reference(StoreEntry &e)
{
    debugs(47, 3, HERE << "referencing " << &e << " " <<
           e.swap_dirn << "/" << e.swap_filen);

    if (repl->Referenced)
        repl->Referenced(repl, &e, &e.repl);
}

bool
Fs::Ufs::UFSSwapDir::dereference(StoreEntry & e)
{
    debugs(47, 3, HERE << "dereferencing " << &e << " " <<
           e.swap_dirn << "/" << e.swap_filen);

    if (repl->Dereferenced)
        repl->Dereferenced(repl, &e, &e.repl);

    return true; // keep e in the global store_table
}

StoreIOState::Pointer
Fs::Ufs::UFSSwapDir::createStoreIO(StoreEntry &e, StoreIOState::STFNCB * file_callback, StoreIOState::STIOCB * aCallback, void *callback_data)
{
    return IO->create (this, &e, file_callback, aCallback, callback_data);
}

StoreIOState::Pointer
Fs::Ufs::UFSSwapDir::openStoreIO(StoreEntry &e, StoreIOState::STFNCB * file_callback, StoreIOState::STIOCB * aCallback, void *callback_data)
{
    return IO->open (this, &e, file_callback, aCallback, callback_data);
}

int
Fs::Ufs::UFSSwapDir::mapBitTest(sfileno filn)
{
    return map->testBit(filn);
}

void
Fs::Ufs::UFSSwapDir::mapBitSet(sfileno filn)
{
    map->setBit(filn);
}

void
Fs::Ufs::UFSSwapDir::mapBitReset(sfileno filn)
{
    /*
     * We have to test the bit before calling clearBit as
     * it doesn't do bounds checking and blindly assumes
     * filn is a valid file number, but it might not be because
     * the map is dynamic in size.  Also clearing an already clear
     * bit puts the map counter of-of-whack.
     */

    if (map->testBit(filn))
        map->clearBit(filn);
}

int
Fs::Ufs::UFSSwapDir::mapBitAllocate()
{
    int fn;
    fn = map->allocate(suggest);
    map->setBit(fn);
    suggest = fn + 1;
    return fn;
}

char *
Fs::Ufs::UFSSwapDir::swapSubDir(int subdirn)const
{
    LOCAL_ARRAY(char, fullfilename, MAXPATHLEN);
    assert(0 <= subdirn && subdirn < l1);
    snprintf(fullfilename, MAXPATHLEN, "%s/%02X", path, subdirn);
    return fullfilename;
}

int
Fs::Ufs::UFSSwapDir::createDirectory(const char *aPath, int should_exist)
{
    int created = 0;

    struct stat st;
    getCurrentTime();

    if (0 == ::stat(aPath, &st)) {
        if (S_ISDIR(st.st_mode)) {
            debugs(47, (should_exist ? 3 : DBG_IMPORTANT), aPath << " exists");
        } else {
            fatalf("Swap directory %s is not a directory.", aPath);
        }
    } else if (0 == mkdir(aPath, 0755)) {
        debugs(47, (should_exist ? DBG_IMPORTANT : 3), aPath << " created");
        created = 1;
    } else {
        int xerrno = errno;
        fatalf("Failed to make swap directory %s: %s", aPath, xstrerr(xerrno));
    }

    return created;
}

bool
Fs::Ufs::UFSSwapDir::pathIsDirectory(const char *aPath)const
{

    struct stat sb;

    if (::stat(aPath, &sb) < 0) {
        int xerrno = errno;
        debugs(47, DBG_CRITICAL, "ERROR: " << aPath << ": " << xstrerr(xerrno));
        return false;
    }

    if (S_ISDIR(sb.st_mode) == 0) {
        debugs(47, DBG_CRITICAL, "WARNING: " << aPath << " is not a directory");
        return false;
    }

    return true;
}

bool
Fs::Ufs::UFSSwapDir::verifyCacheDirs()
{
    if (!pathIsDirectory(path))
        return true;

    for (int j = 0; j < l1; ++j) {
        char const *aPath = swapSubDir(j);

        if (!pathIsDirectory(aPath))
            return true;
    }

    return false;
}

void
Fs::Ufs::UFSSwapDir::createSwapSubDirs()
{
    LOCAL_ARRAY(char, name, MAXPATHLEN);

    for (int i = 0; i < l1; ++i) {
        snprintf(name, MAXPATHLEN, "%s/%02X", path, i);

        int should_exist;

        if (createDirectory(name, 0))
            should_exist = 0;
        else
            should_exist = 1;

        debugs(47, DBG_IMPORTANT, "Making directories in " << name);

        for (int k = 0; k < l2; ++k) {
            snprintf(name, MAXPATHLEN, "%s/%02X/%02X", path, i, k);
            createDirectory(name, should_exist);
        }
    }
}

SBuf
Fs::Ufs::UFSSwapDir::logFile(char const *ext) const
{
    SBuf lpath;

    if (Config.Log.swap) {
        static char pathtmp[MAXPATHLEN];
        char *pathtmp2 = xstrncpy(pathtmp, path, MAXPATHLEN - 64);

        // replace all '/' with '.'
        while ((pathtmp2 = strchr(pathtmp2, '/')))
            *pathtmp2 = '.';

        // remove any trailing '.' characters
        int pos = strlen(pathtmp);
        while (pos && pathtmp[pos-1] == '.')
            pathtmp[--pos] = '\0';

        // remove any prefix '.' characters
        for (pathtmp2 = pathtmp; *pathtmp2 == '.'; ++pathtmp2);
        // replace a '%s' (if any) in the config string
        // with the resulting pathtmp2 string
        lpath.appendf(Config.Log.swap, pathtmp2);

        // is pathtmp2 was NOT injected, append numeric file extension
        if (lpath.cmp(Config.Log.swap) == 0) {
            lpath.append(".", 1);
            lpath.appendf("%02d", index);
        }
    } else {
        lpath.append(path);
        lpath.append("/swap.state", 11);
    }

    lpath.append(ext); // may be nil, that is okay.

    return lpath;
}

void
Fs::Ufs::UFSSwapDir::openLog()
{
    if (!IamWorkerProcess())
        return;

    assert(NumberOfUFSDirs || !UFSDirToGlobalDirMapping);
    ++NumberOfUFSDirs;
    assert(NumberOfUFSDirs <= Config.cacheSwap.n_configured);

    if (rebuilding_) { // we did not close the temporary log used for rebuilding
        assert(swaplog_fd >= 0);
        return;
    }

    SBuf logPath(logFile());
    swaplog_fd = file_open(logPath.c_str(), O_WRONLY | O_CREAT | O_BINARY);

    if (swaplog_fd < 0) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, "ERROR opening swap log " << logPath << ": " << xstrerr(xerrno));
        fatal("UFSSwapDir::openLog: Failed to open swap log.");
    }

    debugs(50, 3, HERE << "Cache Dir #" << index << " log opened on FD " << swaplog_fd);
}

void
Fs::Ufs::UFSSwapDir::closeLog()
{
    if (swaplog_fd < 0) /* not open */
        return;

    --NumberOfUFSDirs;
    assert(NumberOfUFSDirs >= 0);
    if (!NumberOfUFSDirs)
        safe_free(UFSDirToGlobalDirMapping);

    if (rebuilding_) // we cannot close the temporary log used for rebuilding
        return;

    file_close(swaplog_fd);

    debugs(47, 3, "Cache Dir #" << index << " log closed on FD " << swaplog_fd);

    swaplog_fd = -1;
}

bool
Fs::Ufs::UFSSwapDir::validL1(int anInt) const
{
    return anInt < l1;
}

bool
Fs::Ufs::UFSSwapDir::validL2(int anInt) const
{
    return anInt < l2;
}

StoreEntry *
Fs::Ufs::UFSSwapDir::addDiskRestore(const cache_key * key,
                                    sfileno file_number,
                                    uint64_t swap_file_sz,
                                    time_t expires,
                                    time_t timestamp,
                                    time_t lastref,
                                    time_t lastmod,
                                    uint32_t refcount,
                                    uint16_t newFlags,
                                    int)
{
    StoreEntry *e = NULL;
    debugs(47, 5, HERE << storeKeyText(key)  <<
           ", fileno="<< std::setfill('0') << std::hex << std::uppercase << std::setw(8) << file_number);
    /* if you call this you'd better be sure file_number is not
     * already in use! */
    e = new StoreEntry();
    e->store_status = STORE_OK;
    e->setMemStatus(NOT_IN_MEMORY);
    e->attachToDisk(index, file_number, SWAPOUT_DONE);
    e->swap_file_sz = swap_file_sz;
    e->lastref = lastref;
    e->timestamp = timestamp;
    e->expires = expires;
    e->lastModified(lastmod);
    e->refcount = refcount;
    e->flags = newFlags;
    e->ping_status = PING_NONE;
    EBIT_CLR(e->flags, ENTRY_VALIDATED);
    mapBitSet(e->swap_filen);
    cur_size += fs.blksize * sizeInBlocks(e->swap_file_sz);
    ++n_disk_objects;
    e->hashInsert(key);
    replacementAdd (e);
    return e;
}

void
Fs::Ufs::UFSSwapDir::rebuild()
{
    ++StoreController::store_dirs_rebuilding;
    eventAdd("storeRebuild", Fs::Ufs::RebuildState::RebuildStep, new Fs::Ufs::RebuildState(this), 0.0, 1);
}

void
Fs::Ufs::UFSSwapDir::closeTmpSwapLog()
{
    assert(rebuilding_);
    rebuilding_ = false;

    SBuf swaplog_path(logFile()); // where the swaplog should be
    SBuf tmp_path(logFile(".new"));

    file_close(swaplog_fd);

    if (!FileRename(tmp_path, swaplog_path)) {
        fatalf("Failed to rename log file " SQUIDSBUFPH " to " SQUIDSBUFPH, SQUIDSBUFPRINT(tmp_path), SQUIDSBUFPRINT(swaplog_path));
    }

    int fd = file_open(swaplog_path.c_str(), O_WRONLY | O_CREAT | O_BINARY);

    if (fd < 0) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, "ERROR: " << swaplog_path << ": " << xstrerr(xerrno));
        fatalf("Failed to open swap log " SQUIDSBUFPH, SQUIDSBUFPRINT(swaplog_path));
    }

    swaplog_fd = fd;
    debugs(47, 3, "Cache Dir #" << index << " log opened on FD " << fd);
}

FILE *
Fs::Ufs::UFSSwapDir::openTmpSwapLog(int *clean_flag, int *zero_flag)
{
    assert(!rebuilding_);

    SBuf swaplog_path(logFile());
    SBuf clean_path(logFile(".last-clean"));
    SBuf new_path(logFile(".new"));

    struct stat log_sb;

    struct stat clean_sb;

    if (::stat(swaplog_path.c_str(), &log_sb) < 0) {
        debugs(47, DBG_IMPORTANT, "Cache Dir #" << index << ": No log file");
        return NULL;
    }

    *zero_flag = log_sb.st_size == 0 ? 1 : 0;
    /* close the existing write-only FD */

    if (swaplog_fd >= 0)
        file_close(swaplog_fd);

    /* open a write-only FD for the new log */
    int fd = file_open(new_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_BINARY);
    if (fd < 0) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, "ERROR: while opening swap log" << new_path << ": " << xstrerr(xerrno));
        fatalf("Failed to open swap log " SQUIDSBUFPH, SQUIDSBUFPRINT(new_path));
    }

    swaplog_fd = fd;
    rebuilding_ = true;

    {
        const StoreSwapLogHeader header;
        MemBuf buf;
        buf.init(header.record_size, header.record_size);
        buf.append(reinterpret_cast<const char*>(&header), sizeof(header));
        // Pad to keep in sync with UFSSwapDir::writeCleanStart().
        memset(buf.space(), 0, header.gapSize());
        buf.appended(header.gapSize());
        file_write(swaplog_fd, -1, buf.content(), buf.contentSize(),
                   NULL, NULL, buf.freeFunc());
    }

    /* open a read-only stream of the old log */
    FILE *fp = fopen(swaplog_path.c_str(), "rb");
    if (!fp) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, "ERROR: while opening " << swaplog_path << ": " << xstrerr(xerrno));
        fatalf("Failed to open swap log for reading " SQUIDSBUFPH, SQUIDSBUFPRINT(swaplog_path));
    }

    memset(&clean_sb, '\0', sizeof(struct stat));

    if (::stat(clean_path.c_str(), &clean_sb) < 0)
        *clean_flag = 0;
    else if (clean_sb.st_mtime < log_sb.st_mtime)
        *clean_flag = 0;
    else
        *clean_flag = 1;

    safeunlink(clean_path.c_str(), 1);

    return fp;
}

/*
 * Begin the process to write clean cache state.  For AUFS this means
 * opening some log files and allocating write buffers.  Return 0 if
 * we succeed, and assign the 'func' and 'data' return pointers.
 */
int
Fs::Ufs::UFSSwapDir::writeCleanStart()
{
    UFSCleanLog *state = new UFSCleanLog(this);
    StoreSwapLogHeader header;
#if HAVE_FCHMOD

    struct stat sb;
#endif

    cleanLog = NULL;
    state->cur = logFile();
    state->newLog = logFile(".clean");
    state->fd = file_open(state->newLog.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_BINARY);

    if (state->fd < 0) {
        delete state;
        return -1;
    }

    state->cln = state->cur;
    state->cln.append(".last-clean");
    state->outbuf = (char *)xcalloc(CLEAN_BUF_SZ, 1);
    state->outbuf_offset = 0;
    /*copy the header */
    memcpy(state->outbuf, &header, sizeof(StoreSwapLogHeader));
    // Leave a gap to keep in sync with UFSSwapDir::openTmpSwapLog().
    memset(state->outbuf + sizeof(StoreSwapLogHeader), 0, header.gapSize());
    state->outbuf_offset += header.record_size;

    state->walker = repl->WalkInit(repl);
    ::unlink(state->cln.c_str());
    debugs(47, 3, HERE << "opened " << state->newLog << ", FD " << state->fd);
#if HAVE_FCHMOD

    if (::stat(state->cur.c_str(), &sb) == 0)
        fchmod(state->fd, sb.st_mode);

#endif

    cleanLog = state;
    return 0;
}

void
Fs::Ufs::UFSSwapDir::writeCleanDone()
{
    UFSCleanLog *state = (UFSCleanLog *)cleanLog;
    int fd;

    if (NULL == state)
        return;

    if (state->fd < 0)
        return;

    state->walker->Done(state->walker);

    if (FD_WRITE_METHOD(state->fd, state->outbuf, state->outbuf_offset) < 0) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, MYNAME << state->newLog << ": write: " << xstrerr(xerrno));
        debugs(50, DBG_CRITICAL, MYNAME << "Current swap logfile not replaced.");
        file_close(state->fd);
        state->fd = -1;
        ::unlink(state->newLog.c_str());
    }

    safe_free(state->outbuf);
    /*
     * You can't rename open files on Microsoft "operating systems"
     * so we have to close before renaming.
     */
    closeLog();
    /* save the fd value for a later test */
    fd = state->fd;
    /* rename */

    if (state->fd >= 0) {
#if _SQUID_OS2_ || _SQUID_WINDOWS_
        file_close(state->fd);
        state->fd = -1;
#endif

        FileRename(state->newLog, state->cur);
        // TODO handle rename errors
    }

    /* touch a timestamp file if we're not still validating */
    if (StoreController::store_dirs_rebuilding)
        (void) 0;
    else if (fd < 0)
        (void) 0;
    else
        file_close(file_open(state->cln.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_BINARY));

    /* close */
    if (state->fd >= 0)
        file_close(state->fd);

    state->fd = -1;

    delete state;

    cleanLog = NULL;
}

/// safely cleans a few unused files if possible
int
Fs::Ufs::UFSSwapDir::HandleCleanEvent()
{
    static int swap_index = 0;
    int i;
    int j = 0;
    int n = 0;

    if (!NumberOfUFSDirs)
        return 0; // probably in the middle of reconfiguration

    if (NULL == UFSDirToGlobalDirMapping) {
        SwapDir *sd;
        /*
         * Initialize the little array that translates UFS cache_dir
         * number into the Config.cacheSwap.swapDirs array index.
         */
        UFSDirToGlobalDirMapping = (int *)xcalloc(NumberOfUFSDirs, sizeof(*UFSDirToGlobalDirMapping));

        for (i = 0, n = 0; i < Config.cacheSwap.n_configured; ++i) {
            /* This is bogus, the controller should just clean each instance once */
            sd = dynamic_cast <SwapDir *>(INDEXSD(i));

            if (!UFSSwapDir::IsUFSDir(sd))
                continue;

            UFSSwapDir *usd = dynamic_cast<UFSSwapDir *>(sd);

            assert (usd);

            UFSDirToGlobalDirMapping[n] = i;
            ++n;

            j += (usd->l1 * usd->l2);
        }

        assert(n == NumberOfUFSDirs);
        /*
         * Start the commonUfsDirClean() swap_index with a random
         * value.  j equals the total number of UFS level 2
         * swap directories
         */
        std::mt19937 mt(static_cast<uint32_t>(getCurrentTime() & 0xFFFFFFFF));
        xuniform_int_distribution<> dist(0, j);
        swap_index = dist(mt);
    }

    /* if the rebuild is finished, start cleaning directories. */
    if (0 == StoreController::store_dirs_rebuilding) {
        n = DirClean(swap_index);
        ++swap_index;
    }

    return n;
}

void
Fs::Ufs::UFSSwapDir::CleanEvent(void *)
{
    const int n = HandleCleanEvent();
    eventAdd("storeDirClean", CleanEvent, NULL,
             15.0 * exp(-0.25 * n), 1);
}

bool
Fs::Ufs::UFSSwapDir::IsUFSDir(SwapDir * sd)
{
    UFSSwapDir *mySD = dynamic_cast<UFSSwapDir *>(sd);
    return (mySD != 0) ;
}

/*
 * XXX: this is broken - it assumes all cache dirs use the same
 * l1 and l2 scheme. -RBC 20021215. Partial fix is in place -
 * if not UFSSwapDir return 0;
 */
bool
Fs::Ufs::UFSSwapDir::FilenoBelongsHere(int fn, int F0, int F1, int F2)
{
    int D1, D2;
    int L1, L2;
    int filn = fn;
    assert(F0 < Config.cacheSwap.n_configured);
    assert (UFSSwapDir::IsUFSDir (dynamic_cast<SwapDir *>(INDEXSD(F0))));
    UFSSwapDir *sd = dynamic_cast<UFSSwapDir *>(INDEXSD(F0));

    if (!sd)
        return 0;

    L1 = sd->l1;

    L2 = sd->l2;

    D1 = ((filn / L2) / L2) % L1;

    if (F1 != D1)
        return 0;

    D2 = (filn / L2) % L2;

    if (F2 != D2)
        return 0;

    return 1;
}

int
Fs::Ufs::UFSSwapDir::validFileno(sfileno filn, int flag) const
{
    if (filn < 0)
        return 0;

    /*
     * If flag is set it means out-of-range file number should
     * be considered invalid.
     */
    if (flag)
        if (filn > map->capacity())
            return 0;

    return 1;
}

void
Fs::Ufs::UFSSwapDir::unlinkFile(sfileno f)
{
    debugs(79, 3, HERE << "unlinking fileno " <<  std::setfill('0') <<
           std::hex << std::uppercase << std::setw(8) << f << " '" <<
           fullPath(f,NULL) << "'");
    /* commonUfsDirMapBitReset(this, f); */
    IO->unlinkFile(fullPath(f,NULL));
}

bool
Fs::Ufs::UFSSwapDir::unlinkdUseful() const
{
    // unlinkd may be useful only in workers
    return IamWorkerProcess() && IO->io->unlinkdUseful();
}

void
Fs::Ufs::UFSSwapDir::evictCached(StoreEntry & e)
{
    debugs(79, 3, e);
    if (e.locked()) // somebody else may still be using this file
        return; // nothing to do: our get() always returns nil

    if (!e.hasDisk())
        return; // see evictIfFound()

    // Since these fields grow only after swap out ends successfully,
    // do not decrement them for e.swappingOut() and e.swapoutFailed().
    if (e.swappedOut()) {
        cur_size -= fs.blksize * sizeInBlocks(e.swap_file_sz);
        --n_disk_objects;
    }
    replacementRemove(&e);
    mapBitReset(e.swap_filen);
    UFSSwapDir::unlinkFile(e.swap_filen);
    e.detachFromDisk();
}

void
Fs::Ufs::UFSSwapDir::evictIfFound(const cache_key *)
{
    // UFS disk entries always have (attached) StoreEntries so if we got here,
    // the entry is not cached on disk and there is nothing for us to do.
}

void
Fs::Ufs::UFSSwapDir::replacementAdd(StoreEntry * e)
{
    debugs(47, 4, HERE << "added node " << e << " to dir " << index);
    repl->Add(repl, e, &e->repl);
}

void
Fs::Ufs::UFSSwapDir::replacementRemove(StoreEntry * e)
{
    assert(e->hasDisk());

    SwapDirPointer SD = INDEXSD(e->swap_dirn);

    assert (dynamic_cast<UFSSwapDir *>(SD.getRaw()) == this);

    debugs(47, 4, HERE << "remove node " << e << " from dir " << index);

    repl->Remove(repl, e, &e->repl);
}

void
Fs::Ufs::UFSSwapDir::dump(StoreEntry & entry) const
{
    storeAppendPrintf(&entry, " %" PRIu64 " %d %d", maxSize() >> 20, l1, l2);
    dumpOptions(&entry);
}

char *
Fs::Ufs::UFSSwapDir::fullPath(sfileno filn, char *fullpath) const
{
    LOCAL_ARRAY(char, fullfilename, MAXPATHLEN);
    int L1 = l1;
    int L2 = l2;

    if (!fullpath)
        fullpath = fullfilename;

    fullpath[0] = '\0';

    snprintf(fullpath, MAXPATHLEN, "%s/%02X/%02X/%08X",
             path,
             ((filn / L2) / L2) % L1,
             (filn / L2) % L2,
             filn);

    return fullpath;
}

int
Fs::Ufs::UFSSwapDir::callback()
{
    return IO->callback();
}

void
Fs::Ufs::UFSSwapDir::sync()
{
    IO->sync();
}

void
Fs::Ufs::UFSSwapDir::finalizeSwapoutSuccess(const StoreEntry &e)
{
    cur_size += fs.blksize * sizeInBlocks(e.swap_file_sz);
    ++n_disk_objects;
}

void
Fs::Ufs::UFSSwapDir::finalizeSwapoutFailure(StoreEntry &entry)
{
    debugs(47, 5, entry);
    // rely on the expected eventual StoreEntry::release(), evictCached(), or
    // a similar call to call unlink(), detachFromDisk(), etc. for the entry.
}

void
Fs::Ufs::UFSSwapDir::logEntry(const StoreEntry & e, int op) const
{
    if (swaplog_fd < 0) {
        debugs(36, 5, "cannot log " << e << " in the middle of reconfiguration");
        return;
    }

    StoreSwapLogData *s = new StoreSwapLogData;
    s->op = (char) op;
    s->swap_filen = e.swap_filen;
    s->timestamp = e.timestamp;
    s->lastref = e.lastref;
    s->expires = e.expires;
    s->lastmod = e.lastModified();
    s->swap_file_sz = e.swap_file_sz;
    s->refcount = e.refcount;
    s->flags = e.flags;
    memcpy(s->key, e.key, SQUID_MD5_DIGEST_LENGTH);
    s->finalize();
    file_write(swaplog_fd,
               -1,
               s,
               sizeof(StoreSwapLogData),
               NULL,
               NULL,
               FreeObject);
}

int
Fs::Ufs::UFSSwapDir::DirClean(int swap_index)
{
    DIR *dir_pointer = NULL;
    int files[20];
    int swapfileno;
    int fn;         /* same as swapfileno, but with dirn bits set */
    int n = 0;
    int k = 0;
    int N0, N1, N2;
    int D0, D1, D2;
    UFSSwapDir *SD;
    N0 = NumberOfUFSDirs;
    D0 = UFSDirToGlobalDirMapping[swap_index % N0];
    SD = dynamic_cast<UFSSwapDir *>(INDEXSD(D0));
    assert (SD);
    N1 = SD->l1;
    D1 = (swap_index / N0) % N1;
    N2 = SD->l2;
    D2 = ((swap_index / N0) / N1) % N2;

    SBuf p1;
    p1.appendf("%s/%02X/%02X", SD->path, D1, D2);
    debugs(36, 3, HERE << "Cleaning directory " << p1);
    dir_pointer = opendir(p1.c_str());

    if (!dir_pointer) {
        int xerrno = errno;
        if (xerrno == ENOENT) {
            debugs(36, DBG_CRITICAL, MYNAME << "WARNING: Creating " << p1);
            if (mkdir(p1.c_str(), 0777) == 0)
                return 0;
        }

        debugs(50, DBG_CRITICAL, MYNAME << p1 << ": " << xstrerr(xerrno));
        safeunlink(p1.c_str(), 1);
        return 0;
    }

    dirent_t *de;
    while ((de = readdir(dir_pointer)) != NULL && k < 20) {
        if (sscanf(de->d_name, "%X", &swapfileno) != 1)
            continue;

        fn = swapfileno;    /* XXX should remove this cruft ! */

        if (SD->validFileno(fn, 1))
            if (SD->mapBitTest(fn))
                if (UFSSwapDir::FilenoBelongsHere(fn, D0, D1, D2))
                    continue;

        files[k] = swapfileno;
        ++k;
    }

    closedir(dir_pointer);

    if (k == 0)
        return 0;

    qsort(files, k, sizeof(int), rev_int_sort);

    if (k > 10)
        k = 10;

    for (n = 0; n < k; ++n) {
        debugs(36, 3, HERE << "Cleaning file "<< std::setfill('0') << std::hex << std::uppercase << std::setw(8) << files[n]);
        SBuf p2(p1);
        p2.appendf("/%08X", files[n]);
        safeunlink(p2.c_str(), 0);
        ++statCounter.swap.files_cleaned;
    }

    debugs(36, 3, HERE << "Cleaned " << k << " unused files from " << p1);
    return k;
}

