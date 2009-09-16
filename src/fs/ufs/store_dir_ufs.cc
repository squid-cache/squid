
/*
 * $Id$
 *
 * DEBUG: section 47    Store Directory Routines
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "Store.h"
#include "fde.h"
#include "ufscommon.h"
#include "StoreSwapLogData.h"
#include "ConfigOption.h"
#include "DiskIO/DiskIOStrategy.h"
#include "DiskIO/DiskIOModule.h"
#include "Parsing.h"
#include "SquidTime.h"
#include "SwapDir.h"

int UFSSwapDir::NumberOfUFSDirs = 0;
int *UFSSwapDir::UFSDirToGlobalDirMapping = NULL;

/*
 * storeUfsDirCheckObj
 *
 * This routine is called by storeDirSelectSwapDir to see if the given
 * object is able to be stored on this filesystem. UFS filesystems will
 * happily store anything as long as the LRU time isn't too small.
 */
int
UFSSwapDir::canStore(StoreEntry const &e)const
{
    if (IO->shedLoad())
        return -1;

    return IO->load();
}


/* ========== LOCAL FUNCTIONS ABOVE, GLOBAL FUNCTIONS BELOW ========== */

void
UFSSwapDir::parseSizeL1L2()
{
    int i;
    int size;

    i = GetInteger();
    size = i << 10;		/* Mbytes to kbytes */

    if (size <= 0)
        fatal("UFSSwapDir::parseSizeL1L2: invalid size value");

    /* just reconfigure it */
    if (reconfiguring) {
        if (size == max_size)
            debugs(3, 2, "Cache dir '" << path << "' size remains unchanged at " << size << " KB");
        else
            debugs(3, 1, "Cache dir '" << path << "' size changed to " << size << " KB");
    }

    max_size = size;

    l1 = GetInteger();

    if (l1 <= 0)
        fatal("UFSSwapDir::parseSizeL1L2: invalid level 1 directories value");

    l2 = GetInteger();

    if (l2 <= 0)
        fatal("UFSSwapDir::parseSizeL1L2: invalid level 2 directories value");
}

/*
 * storeUfsDirReconfigure
 *
 * This routine is called when the given swapdir needs reconfiguring
 */

void
UFSSwapDir::reconfigure(int index, char *path)
{
    parseSizeL1L2();
    parseOptions(1);
}

/*
 * storeUfsDirParse
 *
 * Called when a *new* fs is being setup.
 */
void
UFSSwapDir::parse (int anIndex, char *aPath)
{
    index = anIndex;
    path = xstrdup(aPath);

    parseSizeL1L2();

    /* Initialise replacement policy stuff */
    repl = createRemovalPolicy(Config.replPolicy);

    parseOptions(0);
}

void
UFSSwapDir::changeIO(DiskIOModule *module)
{
    DiskIOStrategy *anIO = module->createStrategy();
    safe_free(ioType);
    ioType = xstrdup(module->type());

    delete IO->io;
    IO->io = anIO;
    /* Change the IO Options */

    if (currentIOOptions && currentIOOptions->options.size() > 2)
        delete currentIOOptions->options.pop_back();

    /* TODO: factor out these 4 lines */
    ConfigOption *ioOptions = IO->io->getOptionTree();

    if (ioOptions)
        currentIOOptions->options.push_back(ioOptions);
}

bool
UFSSwapDir::optionIOParse(char const *option, const char *value, int reconfiguring)
{
    if (strcmp(option, "IOEngine") != 0)
        return false;

    if (reconfiguring)
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
UFSSwapDir::optionIODump(StoreEntry * e) const
{
    storeAppendPrintf(e, " IOEngine=%s", ioType);
}

ConfigOption *
UFSSwapDir::getOptionTree() const
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

/*
 * Initial setup / end destruction
 */
void
UFSSwapDir::init()
{
    debugs(47, 3, "Initialising UFS SwapDir engine.");
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
UFSSwapDir::create()
{
    debugs(47, 3, "Creating swap space in " << path);
    createDirectory(path, 0);
    createSwapSubDirs();
}

UFSSwapDir::UFSSwapDir(char const *aType, const char *anIOType) : SwapDir(aType), IO(NULL), map(file_map_create()), suggest(0), swaplog_fd (-1), currentIOOptions(new ConfigOptionVector()), ioType(xstrdup(anIOType))
{
    /* modulename is only set to disk modules that are built, by configure,
     * so the Find call should never return NULL here.
     */
    IO = new UFSStrategy(DiskIOModule::Find(anIOType)->createStrategy());
}

UFSSwapDir::~UFSSwapDir()
{
    if (swaplog_fd > -1) {
        file_close(swaplog_fd);
        swaplog_fd = -1;
    }

    filemapFreeMemory(map);

    if (IO)
        delete IO;

    IO = NULL;

    safe_free(ioType);
}

void
UFSSwapDir::dumpEntry(StoreEntry &e) const
{
    debugs(47, 0, "UFSSwapDir::dumpEntry: FILENO "<< std::setfill('0') << std::hex << std::uppercase << std::setw(8) << e.swap_filen);
    debugs(47, 0, "UFSSwapDir::dumpEntry: PATH " << fullPath(e.swap_filen, NULL)   );
    e.dump(0);
}

/*
 * UFSSwapDir::doubleCheck
 *
 * This is called by storeCleanup() if -S was given on the command line.
 */
bool
UFSSwapDir::doubleCheck(StoreEntry & e)
{

    struct stat sb;

    if (::stat(fullPath(e.swap_filen, NULL), &sb) < 0) {
        debugs(47, 0, "UFSSwapDir::doubleCheck: MISSING SWAP FILE");
        dumpEntry(e);
        return true;
    }

    if ((off_t)e.swap_file_sz != sb.st_size) {
        debugs(47, 0, "UFSSwapDir::doubleCheck: SIZE MISMATCH");
        debugs(47, 0, "UFSSwapDir::doubleCheck: ENTRY SIZE: " << e.swap_file_sz << ", FILE SIZE: " << sb.st_size);
        dumpEntry(e);
        return true;
    }

    return false;
}

void
UFSSwapDir::statfs(StoreEntry & sentry) const
{
    int totl_kb = 0;
    int free_kb = 0;
    int totl_in = 0;
    int free_in = 0;
    int x;
    storeAppendPrintf(&sentry, "First level subdirectories: %d\n", l1);
    storeAppendPrintf(&sentry, "Second level subdirectories: %d\n", l2);
    storeAppendPrintf(&sentry, "Maximum Size: %d KB\n", max_size);
    storeAppendPrintf(&sentry, "Current Size: %d KB\n", cur_size);
    storeAppendPrintf(&sentry, "Percent Used: %0.2f%%\n",
                      100.0 * cur_size / max_size);
    storeAppendPrintf(&sentry, "Filemap bits in use: %d of %d (%d%%)\n",
                      map->n_files_in_map, map->max_n_files,
                      percent(map->n_files_in_map, map->max_n_files));
    x = storeDirGetUFSStats(path, &totl_kb, &free_kb, &totl_in, &free_in);

    if (0 == x) {
        storeAppendPrintf(&sentry, "Filesystem Space in use: %d/%d KB (%d%%)\n",
                          totl_kb - free_kb,
                          totl_kb,
                          percent(totl_kb - free_kb, totl_kb));
        storeAppendPrintf(&sentry, "Filesystem Inodes in use: %d/%d (%d%%)\n",
                          totl_in - free_in,
                          totl_in,
                          percent(totl_in - free_in, totl_in));
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
UFSSwapDir::maintain()
{
    /* We can't delete objects while rebuilding swap */

    /* XXX FIXME each store should start maintaining as it comes online. */

    if (StoreController::store_dirs_rebuilding)
        return;

    StoreEntry *e = NULL;

    int removed = 0;

    RemovalPurgeWalker *walker;

    double f = (double) (cur_size - minSize()) / (max_size - minSize());

    f = f < 0.0 ? 0.0 : f > 1.0 ? 1.0 : f;

    int max_scan = (int) (f * 400.0 + 100.0);

    int max_remove = (int) (f * 70.0 + 10.0);

    /*
     * This is kinda cheap, but so we need this priority hack?
     */

    debugs(47, 3, "storeMaintainSwapSpace: f=" << f << ", max_scan=" << max_scan << ", max_remove=" << max_remove  );

    walker = repl->PurgeInit(repl, max_scan);

    while (1) {
        if (cur_size < (int) minSize()) /* cur_size should be unsigned */
            break;

        if (removed >= max_remove)
            break;

        e = walker->Next(walker);

        if (!e)
            break;		/* no more objects */

        removed++;

        e->release();
    }

    walker->Done(walker);
    debugs(47, (removed ? 2 : 3), "UFSSwapDir::maintain: " << path <<
           " removed " << removed << "/" << max_remove << " f=" <<
           std::setprecision(4) << f << " max_scan=" << max_scan);
}

/*
 * UFSSwapDir::reference
 *
 * This routine is called whenever an object is referenced, so we can
 * maintain replacement information within the storage fs.
 */
void
UFSSwapDir::reference(StoreEntry &e)
{
    debugs(47, 3, "UFSSwapDir::reference: referencing " << &e << " " << e.swap_dirn << "/" << e.swap_filen);

    if (repl->Referenced)
        repl->Referenced(repl, &e, &e.repl);
}

/*
 * UFSSwapDir::dereference
 * This routine is called whenever the last reference to an object is
 * removed, to maintain replacement information within the storage fs.
 */
void
UFSSwapDir::dereference(StoreEntry & e)
{
    debugs(47, 3, "UFSSwapDir::dereference: referencing " << &e << " " << e.swap_dirn << "/" << e.swap_filen);

    if (repl->Dereferenced)
        repl->Dereferenced(repl, &e, &e.repl);
}

StoreIOState::Pointer
UFSSwapDir::createStoreIO(StoreEntry &e, StoreIOState::STFNCB * file_callback, StoreIOState::STIOCB * callback, void *callback_data)
{
    return IO->create (this, &e, file_callback, callback, callback_data);
}

StoreIOState::Pointer
UFSSwapDir::openStoreIO(StoreEntry &e, StoreIOState::STFNCB * file_callback, StoreIOState::STIOCB * callback, void *callback_data)
{
    return IO->open (this, &e, file_callback, callback, callback_data);
}

int
UFSSwapDir::mapBitTest(sfileno filn)
{
    return file_map_bit_test(map, filn);
}

void
UFSSwapDir::mapBitSet(sfileno filn)
{
    file_map_bit_set(map, filn);
}

void
UFSSwapDir::mapBitReset(sfileno filn)
{
    /*
     * We have to test the bit before calling file_map_bit_reset.
     * file_map_bit_reset doesn't do bounds checking.  It assumes
     * filn is a valid file number, but it might not be because
     * the map is dynamic in size.  Also clearing an already clear
     * bit puts the map counter of-of-whack.
     */

    if (file_map_bit_test(map, filn))
        file_map_bit_reset(map, filn);
}

int
UFSSwapDir::mapBitAllocate()
{
    int fn;
    fn = file_map_allocate(map, suggest);
    file_map_bit_set(map, fn);
    suggest = fn + 1;
    return fn;
}

char *
UFSSwapDir::swapSubDir(int subdirn)const
{
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    assert(0 <= subdirn && subdirn < l1);
    snprintf(fullfilename, SQUID_MAXPATHLEN, "%s/%02X", path, subdirn);
    return fullfilename;
}

int
UFSSwapDir::createDirectory(const char *path, int should_exist)
{
    int created = 0;

    struct stat st;
    getCurrentTime();

    if (0 == ::stat(path, &st)) {
        if (S_ISDIR(st.st_mode)) {
            debugs(47, (should_exist ? 3 : 1), path << " exists");
        } else {
            fatalf("Swap directory %s is not a directory.", path);
        }

#ifdef _SQUID_MSWIN_

    } else if (0 == mkdir(path)) {
#else

    } else if (0 == mkdir(path, 0755)) {
#endif
        debugs(47, (should_exist ? 1 : 3), path << " created");
        created = 1;
    } else {
        fatalf("Failed to make swap directory %s: %s",
               path, xstrerror());
    }

    return created;
}

bool
UFSSwapDir::pathIsDirectory(const char *path)const
{

    struct stat sb;

    if (::stat(path, &sb) < 0) {
        debugs(47, 0, "" << path << ": " << xstrerror());
        return false;
    }

    if (S_ISDIR(sb.st_mode) == 0) {
        debugs(47, 0, "" << path << " is not a directory");
        return false;
    }

    return true;
}

/*
 * This function is called by commonUfsDirInit().  If this returns < 0,
 * then Squid exits, complains about swap directories not
 * existing, and instructs the admin to run 'squid -z'
 */
bool
UFSSwapDir::verifyCacheDirs()
{
    if (!pathIsDirectory(path))
        return true;

    for (int j = 0; j < l1; j++) {
        char const *aPath = swapSubDir(j);

        if (!pathIsDirectory(aPath))
            return true;
    }

    return false;
}

void
UFSSwapDir::createSwapSubDirs()
{
    LOCAL_ARRAY(char, name, MAXPATHLEN);

    for (int i = 0; i < l1; i++) {
        snprintf(name, MAXPATHLEN, "%s/%02X", path, i);

        int should_exist;

        if (createDirectory(name, 0))
            should_exist = 0;
        else
            should_exist = 1;

        debugs(47, 1, "Making directories in " << name);

        for (int k = 0; k < l2; k++) {
            snprintf(name, MAXPATHLEN, "%s/%02X/%02X", path, i, k);
            createDirectory(name, should_exist);
        }
    }
}

char *
UFSSwapDir::logFile(char const *ext) const
{
    LOCAL_ARRAY(char, lpath, SQUID_MAXPATHLEN);
    LOCAL_ARRAY(char, pathtmp, SQUID_MAXPATHLEN);
    LOCAL_ARRAY(char, digit, 32);
    char *pathtmp2;

    if (Config.Log.swap) {
        xstrncpy(pathtmp, path, SQUID_MAXPATHLEN - 64);
        pathtmp2 = pathtmp;

        while ((pathtmp2 = strchr(pathtmp2, '/')) != NULL)
            *pathtmp2 = '.';

        while (strlen(pathtmp) && pathtmp[strlen(pathtmp) - 1] == '.')
            pathtmp[strlen(pathtmp) - 1] = '\0';

        for (pathtmp2 = pathtmp; *pathtmp2 == '.'; pathtmp2++);
        snprintf(lpath, SQUID_MAXPATHLEN - 64, Config.Log.swap, pathtmp2);

        if (strncmp(lpath, Config.Log.swap, SQUID_MAXPATHLEN - 64) == 0) {
            strcat(lpath, ".");
            snprintf(digit, 32, "%02d", index);
            strncat(lpath, digit, 3);
        }
    } else {
        xstrncpy(lpath, path, SQUID_MAXPATHLEN - 64);
        strcat(lpath, "/swap.state");
    }

    if (ext)
        strncat(lpath, ext, 16);

    return lpath;
}

void
UFSSwapDir::openLog()
{
    char *logPath;
    logPath = logFile();
    swaplog_fd = file_open(logPath, O_WRONLY | O_CREAT | O_BINARY);

    if (swaplog_fd < 0) {
        debugs(50, 1, "" << logPath << ": " << xstrerror());
        fatal("commonUfsDirOpenSwapLog: Failed to open swap log.");
    }

    debugs(50, 3, "Cache Dir #" << index << " log opened on FD " << swaplog_fd);

    if (0 == NumberOfUFSDirs)
        assert(NULL == UFSDirToGlobalDirMapping);

    ++NumberOfUFSDirs;

    assert(NumberOfUFSDirs <= Config.cacheSwap.n_configured);
}

void
UFSSwapDir::closeLog()
{
    if (swaplog_fd < 0)	/* not open */
        return;

    file_close(swaplog_fd);

    debugs(47, 3, "Cache Dir #" << index << " log closed on FD " << swaplog_fd);

    swaplog_fd = -1;

    --NumberOfUFSDirs;

    assert(NumberOfUFSDirs >= 0);

    if (0 == NumberOfUFSDirs)
        safe_free(UFSDirToGlobalDirMapping);
}

bool
UFSSwapDir::validL1(int anInt) const
{
    return anInt < l1;
}

bool
UFSSwapDir::validL2(int anInt) const
{
    return anInt < l2;
}

/* Add a new object to the cache with empty memory copy and pointer to disk
 * use to rebuild store from disk. */
StoreEntry *
UFSSwapDir::addDiskRestore(const cache_key * key,
                           sfileno file_number,
                           uint64_t swap_file_sz,
                           time_t expires,
                           time_t timestamp,
                           time_t lastref,
                           time_t lastmod,
                           u_int32_t refcount,
                           u_int16_t flags,
                           int clean)
{
    StoreEntry *e = NULL;
    debugs(47, 5, "commonUfsAddDiskRestore: " << storeKeyText(key)  <<
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
    e->lock_count = 0;
    e->lastref = lastref;
    e->timestamp = timestamp;
    e->expires = expires;
    e->lastmod = lastmod;
    e->refcount = refcount;
    e->flags = flags;
    EBIT_SET(e->flags, ENTRY_CACHABLE);
    EBIT_CLR(e->flags, RELEASE_REQUEST);
    EBIT_CLR(e->flags, KEY_PRIVATE);
    e->ping_status = PING_NONE;
    EBIT_CLR(e->flags, ENTRY_VALIDATED);
    mapBitSet(e->swap_filen);
    e->hashInsert(key);	/* do it after we clear KEY_PRIVATE */
    replacementAdd (e);
    return e;
}

void
UFSSwapDir::rebuild()
{
    ++StoreController::store_dirs_rebuilding;
    eventAdd("storeRebuild", RebuildState::RebuildStep, new RebuildState(this), 0.0, 1);
}

void
UFSSwapDir::closeTmpSwapLog()
{
    char *swaplog_path = xstrdup(logFile(NULL));
    char *new_path = xstrdup(logFile(".new"));
    int fd;
    file_close(swaplog_fd);

    if (xrename(new_path, swaplog_path) < 0) {
        fatal("commonUfsDirCloseTmpSwapLog: rename failed");
    }

    fd = file_open(swaplog_path, O_WRONLY | O_CREAT | O_BINARY);

    if (fd < 0) {
        debugs(50, 1, "" << swaplog_path << ": " << xstrerror());
        fatal("commonUfsDirCloseTmpSwapLog: Failed to open swap log.");
    }

    safe_free(swaplog_path);
    safe_free(new_path);
    swaplog_fd = fd;
    debugs(47, 3, "Cache Dir #" << index << " log opened on FD " << fd);
}

static void
FreeHeader(void *address)
{
    StoreSwapLogHeader *anObject = static_cast <StoreSwapLogHeader *>(address);
    delete anObject;
}

FILE *
UFSSwapDir::openTmpSwapLog(int *clean_flag, int *zero_flag)
{
    char *swaplog_path = xstrdup(logFile(NULL));
    char *clean_path = xstrdup(logFile(".last-clean"));
    char *new_path = xstrdup(logFile(".new"));

    struct stat log_sb;

    struct stat clean_sb;
    FILE *fp;
    int fd;
    StoreSwapLogHeader *head;

    if (::stat(swaplog_path, &log_sb) < 0) {
        debugs(47, 1, "Cache Dir #" << index << ": No log file");
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
        debugs(50, 1, "" << new_path << ": " << xstrerror());
        fatal("storeDirOpenTmpSwapLog: Failed to open swap log.");
    }

    swaplog_fd = fd;

    head = new StoreSwapLogHeader;

    file_write(swaplog_fd, -1, head, head->record_size,
               NULL, NULL, FreeHeader);

    /* open a read-only stream of the old log */
    fp = fopen(swaplog_path, "rb");

    if (fp == NULL) {
        debugs(50, 0, "" << swaplog_path << ": " << xstrerror());
        fatal("Failed to open swap log for reading");
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

class UFSCleanLog : public SwapDir::CleanLog
{

public:
    UFSCleanLog(SwapDir *);
    virtual const StoreEntry *nextEntry();
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

#define CLEAN_BUF_SZ 16384


UFSCleanLog::UFSCleanLog(SwapDir *aSwapDir) : cur(NULL),newLog(NULL),cln(NULL),outbuf(NULL),
        outbuf_offset(0), fd(-1),walker(NULL), sd(aSwapDir)
{}

/*
 * Begin the process to write clean cache state.  For AUFS this means
 * opening some log files and allocating write buffers.  Return 0 if
 * we succeed, and assign the 'func' and 'data' return pointers.
 */
int
UFSSwapDir::writeCleanStart()
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
    xmemcpy(state->outbuf, &header, sizeof(StoreSwapLogHeader));
    state->outbuf_offset += header.record_size;

    state->walker = repl->WalkInit(repl);
    ::unlink(state->cln);
    debugs(47, 3, "storeDirWriteCleanLogs: opened " << state->newLog << ", FD " << state->fd);
#if HAVE_FCHMOD

    if (::stat(state->cur, &sb) == 0)
        fchmod(state->fd, sb.st_mode);

#endif


    cleanLog = state;
    return 0;
}

/*
 * Get the next entry that is a candidate for clean log writing
 */
const StoreEntry *
UFSCleanLog::nextEntry()
{
    const StoreEntry *entry = NULL;

    if (walker)
        entry = walker->Next(walker);

    return entry;
}

/*
 * "write" an entry to the clean log file.
 */
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
    s.lastmod = e.lastmod;
    s.swap_file_sz = e.swap_file_sz;
    s.refcount = e.refcount;
    s.flags = e.flags;
    xmemcpy(&s.key, e.key, SQUID_MD5_DIGEST_LENGTH);
    xmemcpy(outbuf + outbuf_offset, &s, ss);
    outbuf_offset += ss;
    /* buffered write */

    if (outbuf_offset + ss >= CLEAN_BUF_SZ) {
        if (FD_WRITE_METHOD(fd, outbuf, outbuf_offset) < 0) {
            /* XXX This error handling should probably move up to the caller */
            debugs(50, 0, "storeDirWriteCleanLogs: " << newLog << ": write: " << xstrerror());
            debugs(50, 0, "storeDirWriteCleanLogs: Current swap logfile not replaced.");
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

void
UFSSwapDir::writeCleanDone()
{
    UFSCleanLog *state = (UFSCleanLog *)cleanLog;
    int fd;

    if (NULL == state)
        return;

    if (state->fd < 0)
        return;

    state->walker->Done(state->walker);

    if (FD_WRITE_METHOD(state->fd, state->outbuf, state->outbuf_offset) < 0) {
        debugs(50, 0, "storeDirWriteCleanLogs: " << state->newLog << ": write: " << xstrerror());
        debugs(50, 0, "storeDirWriteCleanLogs: Current swap logfile not replaced.");
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
#if defined(_SQUID_OS2_) || defined (_SQUID_WIN32_)
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

static void
FreeObject(void *address)
{
    StoreSwapLogData *anObject = static_cast <StoreSwapLogData *>(address);
    delete anObject;
}

void
UFSSwapDir::logEntry(const StoreEntry & e, int op) const
{
    StoreSwapLogData *s = new StoreSwapLogData;
    s->op = (char) op;
    s->swap_filen = e.swap_filen;
    s->timestamp = e.timestamp;
    s->lastref = e.lastref;
    s->expires = e.expires;
    s->lastmod = e.lastmod;
    s->swap_file_sz = e.swap_file_sz;
    s->refcount = e.refcount;
    s->flags = e.flags;
    xmemcpy(s->key, e.key, SQUID_MD5_DIGEST_LENGTH);
    file_write(swaplog_fd,
               -1,
               s,
               sizeof(StoreSwapLogData),
               NULL,
               NULL,
               FreeObject);
}

static QS rev_int_sort;
static int
rev_int_sort(const void *A, const void *B)
{
    const int *i1 = (const int *)A;
    const int *i2 = (const int *)B;
    return *i2 - *i1;
}

int
UFSSwapDir::DirClean(int swap_index)
{
    DIR *dir_pointer = NULL;

    struct dirent *de = NULL;
    LOCAL_ARRAY(char, p1, MAXPATHLEN + 1);
    LOCAL_ARRAY(char, p2, MAXPATHLEN + 1);

    int files[20];
    int swapfileno;
    int fn;			/* same as swapfileno, but with dirn bits set */
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
    snprintf(p1, SQUID_MAXPATHLEN, "%s/%02X/%02X",
             SD->path, D1, D2);
    debugs(36, 3, "storeDirClean: Cleaning directory " << p1);
    dir_pointer = opendir(p1);

    if (dir_pointer == NULL) {
        if (errno == ENOENT) {
            debugs(36, 0, "storeDirClean: WARNING: Creating " << p1);
#ifdef _SQUID_MSWIN_

            if (mkdir(p1) == 0)
#else

            if (mkdir(p1, 0777) == 0)
#endif

                return 0;
        }

        debugs(50, 0, "storeDirClean: " << p1 << ": " << xstrerror());
        safeunlink(p1, 1);
        return 0;
    }

    while ((de = readdir(dir_pointer)) != NULL && k < 20) {
        if (sscanf(de->d_name, "%X", &swapfileno) != 1)
            continue;

        fn = swapfileno;	/* XXX should remove this cruft ! */

        if (SD->validFileno(fn, 1))
            if (SD->mapBitTest(fn))
                if (UFSSwapDir::FilenoBelongsHere(fn, D0, D1, D2))
                    continue;

        files[k++] = swapfileno;
    }

    closedir(dir_pointer);

    if (k == 0)
        return 0;

    qsort(files, k, sizeof(int), rev_int_sort);

    if (k > 10)
        k = 10;

    for (n = 0; n < k; n++) {
        debugs(36, 3, "storeDirClean: Cleaning file "<< std::setfill('0') << std::hex << std::uppercase << std::setw(8) << files[n]);
        snprintf(p2, MAXPATHLEN + 1, "%s/%08X", p1, files[n]);
        safeunlink(p2, 0);
        statCounter.swap.files_cleaned++;
    }

    debugs(36, 3, "Cleaned " << k << " unused files from " << p1);
    return k;
}

void
UFSSwapDir::CleanEvent(void *unused)
{
    static int swap_index = 0;
    int i;
    int j = 0;
    int n = 0;
    /*
     * Assert that there are UFS cache_dirs configured, otherwise
     * we should never be called.
     */
    assert(NumberOfUFSDirs);

    if (NULL == UFSDirToGlobalDirMapping) {
        SwapDir *sd;
        /*
         * Initialize the little array that translates UFS cache_dir
         * number into the Config.cacheSwap.swapDirs array index.
         */
        UFSDirToGlobalDirMapping = (int *)xcalloc(NumberOfUFSDirs, sizeof(*UFSDirToGlobalDirMapping));

        for (i = 0, n = 0; i < Config.cacheSwap.n_configured; i++) {
            /* This is bogus, the controller should just clean each instance once */
            sd = dynamic_cast <SwapDir *>(INDEXSD(i));

            if (!UFSSwapDir::IsUFSDir(sd))
                continue;

            UFSSwapDir *usd = dynamic_cast<UFSSwapDir *>(sd);

            assert (usd);

            UFSDirToGlobalDirMapping[n++] = i;

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
        swap_index++;
    }

    eventAdd("storeDirClean", CleanEvent, NULL,
             15.0 * exp(-0.25 * n), 1);
}

int
UFSSwapDir::IsUFSDir(SwapDir * sd)
{
    UFSSwapDir *mySD = dynamic_cast<UFSSwapDir *>(sd);
    return mySD ? 1 : 0 ;
}

/*
 * Does swapfile number 'fn' belong in cachedir #F0,
 * level1 dir #F1, level2 dir #F2?
 * XXX: this is broken - it assumes all cache dirs use the same
 * l1 and l2 scheme. -RBC 20021215. Partial fix is in place -
 * if not UFSSwapDir return 0;
 */
int
UFSSwapDir::FilenoBelongsHere(int fn, int F0, int F1, int F2)
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
UFSSwapDir::validFileno(sfileno filn, int flag) const
{
    if (filn < 0)
        return 0;

    /*
     * If flag is set it means out-of-range file number should
     * be considered invalid.
     */
    if (flag)
        if (filn > map->max_n_files)
            return 0;

    return 1;
}



/*
 * UFSSwapDir::unlinkFile
 *
 * This routine unlinks a file and pulls it out of the bitmap.
 * It used to be in commonUfsUnlink(), however an interface change
 * forced this bit of code here. Eeek.
 */
void
UFSSwapDir::unlinkFile(sfileno f)
{
    debugs(79, 3, "UFSSwapDir::unlinkFile: unlinking fileno " <<  std::setfill('0') <<
           std::hex << std::uppercase << std::setw(8) << f << " '" <<
           fullPath(f,NULL) << "'");
    /* commonUfsDirMapBitReset(this, f); */
    IO->unlinkFile(fullPath(f,NULL));
}

void
UFSSwapDir::unlink(StoreEntry & e)
{
    debugs(79, 3, "storeUfsUnlink: dirno " << index  << ", fileno "<<
           std::setfill('0') << std::hex << std::uppercase << std::setw(8) << e.swap_filen);
    replacementRemove(&e);
    mapBitReset(e.swap_filen);
    UFSSwapDir::unlinkFile(e.swap_filen);
}

/*
 * Add and remove the given StoreEntry from the replacement policy in
 * use.
 */

void
UFSSwapDir::replacementAdd(StoreEntry * e)
{
    debugs(47, 4, "UFSSwapDir::replacementAdd: added node " << e << " to dir " << index);
    repl->Add(repl, e, &e->repl);
}


void
UFSSwapDir::replacementRemove(StoreEntry * e)
{
    StorePointer SD;

    if (e->swap_dirn < 0)
        return;

    SD = INDEXSD(e->swap_dirn);

    assert (dynamic_cast<UFSSwapDir *>(SD.getRaw()) == this);

    debugs(47, 4, "UFSSwapDir::replacementRemove: remove node " << e << " from dir " << index);

    repl->Remove(repl, e, &e->repl);
}

void
UFSSwapDir::dump(StoreEntry & entry) const
{
    storeAppendPrintf(&entry, " %d %d %d",
                      max_size >> 10,
                      l1,
                      l2);
    dumpOptions(&entry);
}

char *
UFSSwapDir::fullPath(sfileno filn, char *fullpath) const
{
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    int L1 = l1;
    int L2 = l2;

    if (!fullpath)
        fullpath = fullfilename;

    fullpath[0] = '\0';

    snprintf(fullpath, SQUID_MAXPATHLEN, "%s/%02X/%02X/%08X",
             path,
             ((filn / L2) / L2) % L1,
             (filn / L2) % L2,
             filn);

    return fullpath;
}

int
UFSSwapDir::callback()
{
    return IO->callback();
}

void
UFSSwapDir::sync()
{
    IO->sync();
}

StoreSearch *
UFSSwapDir::search(String const url, HttpRequest *request)
{
    if (url.size())
        fatal ("Cannot search by url yet\n");

    return new StoreSearchUFS (this);
}

CBDATA_CLASS_INIT(StoreSearchUFS);
StoreSearchUFS::StoreSearchUFS(RefCount<UFSSwapDir> aSwapDir) : sd(aSwapDir), walker (sd->repl->WalkInit(sd->repl)), current (NULL), _done (false)
{}

/* do not link
StoreSearchUFS::StoreSearchUFS(StoreSearchUFS const &);
*/

StoreSearchUFS::~StoreSearchUFS()
{
    walker->Done(walker);
    walker = NULL;
}

void
StoreSearchUFS::next(void (callback)(void *cbdata), void *cbdata)
{
    next();
    callback (cbdata);
}

bool
StoreSearchUFS::next()
{
    /* the walker API doesn't make sense. the store entries referred to are already readwrite
     * from their hash table entries
     */

    if (walker)
        current = const_cast<StoreEntry *>(walker->Next(walker));

    if (current == NULL)
        _done = true;

    return current != NULL;
}

bool
StoreSearchUFS::error() const
{
    return false;
}

bool
StoreSearchUFS::isDone() const
{
    return _done;
}

StoreEntry *
StoreSearchUFS::currentItem()
{
    return current;
}
