/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
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
#include "disk.h"
#include "DiskIO/DiskIOModule.h"
#include "DiskIO/DiskIOStrategy.h"
#include "fde.h"
#include "FileMap.h"
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
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

int Fs::Ufs::UFSSwapDir::NumberOfUFSDirs = 0;
int *Fs::Ufs::UFSSwapDir::UFSDirToGlobalDirMapping = NULL;

class UFSCleanLog : public SwapDir::CleanLog
{

public:
    UFSCleanLog(SwapDir *);
    /** Get the next entry that is a candidate for clean log writing
     */
    virtual const StoreEntry *nextEntry();
    /** "write" an entry to the clean log file.
     */
    virtual void write(StoreEntry const &);
    char *cur;
    char *newLog;
    char *cln;
    char *outbuf;
    off_t outbuf_offset;
    int fd;
    RemovalPolicyWalker *walker;
    SwapDir *sd;
};

UFSCleanLog::UFSCleanLog(SwapDir *aSwapDir) :
    cur(NULL), newLog(NULL), cln(NULL), outbuf(NULL),
    outbuf_offset(0), fd(-1),walker(NULL), sd(aSwapDir)
{}

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
            /* XXX This error handling should probably move up to the caller */
            debugs(50, DBG_CRITICAL, HERE << newLog << ": write: " << xstrerror());
            debugs(50, DBG_CRITICAL, HERE << "Current swap logfile not replaced.");
            file_close(fd);
            fd = -1;
            unlink(newLog);
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

static QS rev_int_sort;
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

    if (!value)
        self_destruct();

    DiskIOModule *module = DiskIOModule::Find(value);

    if (!module)
        self_destruct();

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

    (void) storeDirGetBlkSize(path, &fs.blksize);
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
    x = storeDirGetUFSStats(path, &totl_kb, &free_kb, &totl_in, &free_in);

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

        e->release();
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
Fs::Ufs::UFSSwapDir::dereference(StoreEntry & e, bool)
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
        fatalf("Failed to make swap directory %s: %s",
               aPath, xstrerror());
    }

    return created;
}

bool
Fs::Ufs::UFSSwapDir::pathIsDirectory(const char *aPath)const
{

    struct stat sb;

    if (::stat(aPath, &sb) < 0) {
        debugs(47, DBG_CRITICAL, "ERROR: " << aPath << ": " << xstrerror());
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

char *
Fs::Ufs::UFSSwapDir::logFile(char const *ext) const
{
    LOCAL_ARRAY(char, lpath, MAXPATHLEN);
    LOCAL_ARRAY(char, pathtmp, MAXPATHLEN);
    LOCAL_ARRAY(char, digit, 32);
    char *pathtmp2;

    if (Config.Log.swap) {
        xstrncpy(pathtmp, path, MAXPATHLEN - 64);
        pathtmp2 = pathtmp;

        while ((pathtmp2 = strchr(pathtmp2, '/')) != NULL)
            *pathtmp2 = '.';

        while (strlen(pathtmp) && pathtmp[strlen(pathtmp) - 1] == '.')
            pathtmp[strlen(pathtmp) - 1] = '\0';

        for (pathtmp2 = pathtmp; *pathtmp2 == '.'; ++pathtmp2);
        snprintf(lpath, MAXPATHLEN - 64, Config.Log.swap, pathtmp2);

        if (strncmp(lpath, Config.Log.swap, MAXPATHLEN - 64) == 0) {
            strcat(lpath, ".");
            snprintf(digit, 32, "%02d", index);
            strncat(lpath, digit, 3);
        }
    } else {
        xstrncpy(lpath, path, MAXPATHLEN - 64);
        strcat(lpath, "/swap.state");
    }

    if (ext)
        strncat(lpath, ext, 16);

    return lpath;
}

void
Fs::Ufs::UFSSwapDir::openLog()
{
    assert(NumberOfUFSDirs || !UFSDirToGlobalDirMapping);
    ++NumberOfUFSDirs;
    assert(NumberOfUFSDirs <= Config.cacheSwap.n_configured);

    if (rebuilding_) { // we did not close the temporary log used for rebuilding
        assert(swaplog_fd >= 0);
        return;
    }

    char *logPath;
    logPath = logFile();
    swaplog_fd = file_open(logPath, O_WRONLY | O_CREAT | O_BINARY);

    if (swaplog_fd < 0) {
        debugs(50, DBG_IMPORTANT, "ERROR opening swap log " << logPath << ": " << xstrerror());
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
                                    int clean)
{
    StoreEntry *e = NULL;
    debugs(47, 5, HERE << storeKeyText(key)  <<
           ", fileno="<< std::setfill('0') << std::hex << std::uppercase << std::setw(8) << file_number);
    /* if you call this you'd better be sure file_number is not
     * already in use! */
    e = new StoreEntry();
    e->store_status = STORE_OK;
    e->setMemStatus(NOT_IN_MEMORY);
    e->swap_status = SWAPOUT_DONE;
    e->swap_filen = file_number;
    e->swap_dirn = index;
    e->swap_file_sz = swap_file_sz;
    e->lastref = lastref;
    e->timestamp = timestamp;
    e->expires = expires;
    e->lastModified(lastmod);
    e->refcount = refcount;
    e->flags = newFlags;
    EBIT_CLR(e->flags, RELEASE_REQUEST);
    e->clearPrivate();
    e->ping_status = PING_NONE;
    EBIT_CLR(e->flags, ENTRY_VALIDATED);
    mapBitSet(e->swap_filen);
    cur_size += fs.blksize * sizeInBlocks(e->swap_file_sz);
    ++n_disk_objects;
    e->hashInsert(key); /* do it after we clear KEY_PRIVATE */
    replacementAdd (e);
    return e;
}

void
Fs::Ufs::UFSSwapDir::undoAddDiskRestore(StoreEntry *e)
{
    debugs(47, 5, HERE << *e);
    replacementRemove(e); // checks swap_dirn so do it before we invalidate it
    // Do not unlink the file as it might be used by a subsequent entry.
    mapBitReset(e->swap_filen);
    e->swap_filen = -1;
    e->swap_dirn = -1;
    cur_size -= fs.blksize * sizeInBlocks(e->swap_file_sz);
    --n_disk_objects;
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

    char *swaplog_path = xstrdup(logFile(NULL)); // where the swaplog should be
    char *tmp_path = xstrdup(logFile(".new")); // the temporary file we have generated
    int fd;
    file_close(swaplog_fd);

    if (xrename(tmp_path, swaplog_path) < 0) {
        fatalf("Failed to rename log file %s to %s", tmp_path, swaplog_path);
    }

    fd = file_open(swaplog_path, O_WRONLY | O_CREAT | O_BINARY);

    if (fd < 0) {
        debugs(50, DBG_IMPORTANT, "ERROR: " << swaplog_path << ": " << xstrerror());
        fatalf("Failed to open swap log %s", swaplog_path);
    }

    xfree(swaplog_path);
    xfree(tmp_path);
    swaplog_fd = fd;
    debugs(47, 3, "Cache Dir #" << index << " log opened on FD " << fd);
}

FILE *
Fs::Ufs::UFSSwapDir::openTmpSwapLog(int *clean_flag, int *zero_flag)
{
    assert(!rebuilding_);

    char *swaplog_path = xstrdup(logFile(NULL));
    char *clean_path = xstrdup(logFile(".last-clean"));
    char *new_path = xstrdup(logFile(".new"));

    struct stat log_sb;

    struct stat clean_sb;
    FILE *fp;
    int fd;

    if (::stat(swaplog_path, &log_sb) < 0) {
        debugs(47, DBG_IMPORTANT, "Cache Dir #" << index << ": No log file");
        safe_free(swaplog_path);
        safe_free(clean_path);
        safe_free(new_path);
        return NULL;
    }

    *zero_flag = log_sb.st_size == 0 ? 1 : 0;
    /* close the existing write-only FD */

    if (swaplog_fd >= 0)
        file_close(swaplog_fd);

    /* open a write-only FD for the new log */
    fd = file_open(new_path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY);

    if (fd < 0) {
        debugs(50, DBG_IMPORTANT, "ERROR: while opening swap log" << new_path << ": " << xstrerror());
        fatalf("Failed to open swap log %s", new_path);
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
    fp = fopen(swaplog_path, "rb");

    if (fp == NULL) {
        debugs(50, DBG_CRITICAL, "ERROR: while opening " << swaplog_path << ": " << xstrerror());
        fatalf("Failed to open swap log for reading %s", swaplog_path);
    }

    memset(&clean_sb, '\0', sizeof(struct stat));

    if (::stat(clean_path, &clean_sb) < 0)
        *clean_flag = 0;
    else if (clean_sb.st_mtime < log_sb.st_mtime)
        *clean_flag = 0;
    else
        *clean_flag = 1;

    safeunlink(clean_path, 1);

    safe_free(swaplog_path);

    safe_free(clean_path);

    safe_free(new_path);

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
    state->newLog = xstrdup(logFile(".clean"));
    state->fd = file_open(state->newLog, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY);

    if (state->fd < 0) {
        xfree(state->newLog);
        delete state;
        return -1;
    }

    state->cur = xstrdup(logFile(NULL));
    state->cln = xstrdup(logFile(".last-clean"));
    state->outbuf = (char *)xcalloc(CLEAN_BUF_SZ, 1);
    state->outbuf_offset = 0;
    /*copy the header */
    memcpy(state->outbuf, &header, sizeof(StoreSwapLogHeader));
    // Leave a gap to keep in sync with UFSSwapDir::openTmpSwapLog().
    memset(state->outbuf + sizeof(StoreSwapLogHeader), 0, header.gapSize());
    state->outbuf_offset += header.record_size;

    state->walker = repl->WalkInit(repl);
    ::unlink(state->cln);
    debugs(47, 3, HERE << "opened " << state->newLog << ", FD " << state->fd);
#if HAVE_FCHMOD

    if (::stat(state->cur, &sb) == 0)
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
        debugs(50, DBG_CRITICAL, HERE << state->newLog << ": write: " << xstrerror());
        debugs(50, DBG_CRITICAL, HERE << "Current swap logfile not replaced.");
        file_close(state->fd);
        state->fd = -1;
        ::unlink(state->newLog);
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

        xrename(state->newLog, state->cur);
    }

    /* touch a timestamp file if we're not still validating */
    if (StoreController::store_dirs_rebuilding)
        (void) 0;
    else if (fd < 0)
        (void) 0;
    else
        file_close(file_open(state->cln, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY));

    /* close */
    safe_free(state->cur);

    safe_free(state->newLog);

    safe_free(state->cln);

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
        swap_index = (int) (squid_random() % j);
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
Fs::Ufs::UFSSwapDir::unlink(StoreEntry & e)
{
    debugs(79, 3, HERE << "dirno " << index  << ", fileno "<<
           std::setfill('0') << std::hex << std::uppercase << std::setw(8) << e.swap_filen);
    if (e.swap_status == SWAPOUT_DONE) {
        cur_size -= fs.blksize * sizeInBlocks(e.swap_file_sz);
        --n_disk_objects;
    }
    replacementRemove(&e);
    mapBitReset(e.swap_filen);
    UFSSwapDir::unlinkFile(e.swap_filen);
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
    StorePointer SD;

    if (e->swap_dirn < 0)
        return;

    SD = INDEXSD(e->swap_dirn);

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
Fs::Ufs::UFSSwapDir::swappedOut(const StoreEntry &e)
{
    cur_size += fs.blksize * sizeInBlocks(e.swap_file_sz);
    ++n_disk_objects;
}

StoreSearch *
Fs::Ufs::UFSSwapDir::search(String const url, HttpRequest *request)
{
    if (url.size())
        fatal ("Cannot search by url yet\n");

    return new Fs::Ufs::StoreSearchUFS (this);
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

    LOCAL_ARRAY(char, p1, MAXPATHLEN + 1);
    LOCAL_ARRAY(char, p2, MAXPATHLEN + 1);

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
    snprintf(p1, MAXPATHLEN, "%s/%02X/%02X",
             SD->path, D1, D2);
    debugs(36, 3, HERE << "Cleaning directory " << p1);
    dir_pointer = opendir(p1);

    if (dir_pointer == NULL) {
        if (errno == ENOENT) {
            debugs(36, DBG_CRITICAL, HERE << "WARNING: Creating " << p1);
            if (mkdir(p1, 0777) == 0)
                return 0;
        }

        debugs(50, DBG_CRITICAL, HERE << p1 << ": " << xstrerror());
        safeunlink(p1, 1);
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
        snprintf(p2, MAXPATHLEN + 1, "%s/%08X", p1, files[n]);
        safeunlink(p2, 0);
        ++statCounter.swap.files_cleaned;
    }

    debugs(36, 3, HERE << "Cleaned " << k << " unused files from " << p1);
    return k;
}

