
/*
 * $Id: store_dir_ufs.cc,v 1.54 2003/01/23 00:38:22 robertc Exp $
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
#include "store_ufs.h"
#include "ufscommon.h"

#include "SwapDir.h"
static int ufs_initialised = 0;

int UFSSwapDir::NumberOfUFSDirs = 0;
int *UFSSwapDir::UFSDirToGlobalDirMapping = NULL;

STSETUP storeFsSetup_ufs;

/*
 * storeUfsDirCheckObj
 *
 * This routine is called by storeDirSelectSwapDir to see if the given
 * object is able to be stored on this filesystem. UFS filesystems will
 * happily store anything as long as the LRU time isn't too small.
 */
int
UfsSwapDir::canStore(StoreEntry const &e)const
{
    /* Return 999 (99.9%) constant load */
    return 999;
}

void
UfsSwapDir::unlinkFile(char const *path)
{
#if USE_UNLINKD
    unlinkdUnlink(path);
#elif USE_TRUNCATE
    truncate(path, 0);
#else
    ::unlink(path);
#endif
}

/* ========== LOCAL FUNCTIONS ABOVE, GLOBAL FUNCTIONS BELOW ========== */

static struct cache_dir_option options[] =
{
#if NOT_YET_DONE
    {"L1", storeUfsDirParseL1, storeUfsDirDumpL1},
    {"L2", storeUfsDirParseL2, storeUfsDirDumpL2},
#endif
    {NULL, NULL}
};

/*
 * storeUfsDirReconfigure
 *
 * This routine is called when the given swapdir needs reconfiguring 
 */
void
UfsSwapDir::reconfigure(int anIndex, char *aPath)
{
    UFSSwapDir::reconfigure (anIndex, aPath);
    parse_cachedir_options(this, options, 1);
}

void
UFSSwapDir::reconfigure(int index, char *path)
{
    int i;
    int size;

    i = GetInteger();
    size = i << 10;		/* Mbytes to kbytes */
    if (size <= 0)
	fatal("storeDiskdDirReconfigure: invalid size value");
    l1 = GetInteger();
    if (l1 <= 0)
	fatal("storeDiskdDirReconfigure: invalid level 1 directories value");
    l2 = GetInteger();
    if (l2 <= 0)
	fatal("storeDiskdDirReconfigure: invalid level 2 directories value");

    /* just reconfigure it */
    if (size == max_size)
	debug(3, 1) ("Cache dir '%s' size remains unchanged at %d KB\n",
	    path, size);
    else
	debug(3, 1) ("Cache dir '%s' size changed to %d KB\n",
	    path, size);
    max_size = size;
}

void
UfsSwapDir::dump(StoreEntry & entry)const
{
    UFSSwapDir::dump (entry);
    dump_cachedir_options(&entry, options, this);
}

/*
 * storeUfsDirParse
 *
 * Called when a *new* fs is being setup.
 */
void
UfsSwapDir::parse(int anIndex, char *aPath)
{
    UFSSwapDir::parse (anIndex, aPath);

    parse_cachedir_options(this, options, 1);
}

void
UFSSwapDir::parse (int anIndex, char *aPath)
{
    max_size = GetInteger() << 10;		/* Mbytes to kbytes */
    if (max_size <= 0)
	fatal("storeAufsDirParse: invalid size value");
    l1 = GetInteger();
    if (l1 <= 0)
	fatal("storeAufsDirParse: invalid level 1 directories value");
    l2 = GetInteger();
    if (l2 <= 0)
	fatal("storeAufsDirParse: invalid level 2 directories value");

    index = anIndex;
    path = xstrdup(aPath);

    /* Initialise replacement policy stuff */
    repl = createRemovalPolicy(Config.replPolicy);
}

/*
 * Initial setup / end destruction
 */
void
UFSSwapDir::init()
{
    static int started_clean_event = 0;
    static const char *errmsg =
    "\tFailed to verify one of the swap directories, Check cache.log\n"
    "\tfor details.  Run 'squid -z' to create swap directories\n"
    "\tif needed, or if running Squid for the first time.";
    initBitmap();
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
UFSSwapDir::newFileSystem()
{
    debug(47, 3) ("Creating swap space in %s\n", path);
    createDirectory(path, 0);
    createSwapSubDirs();
}

UFSSwapDir::UFSSwapDir() : IO(NULL), map(NULL), suggest(0), swaplog_fd (-1) {}

UFSSwapDir::~UFSSwapDir()
{
    if (swaplog_fd > -1) {
	file_close(swaplog_fd);
	swaplog_fd = -1;
    }
    filemapFreeMemory(map);
    if (IO)
	IO->deleteSelf();
    IO = NULL;
}

static void
storeUfsDirDone(void)
{
    ufs_initialised = 0;
}

static SwapDir *
storeUfsNew(void)
{
    UfsSwapDir *result = new UfsSwapDir;
    result->IO = &UfsIO::Instance;
    return result;
}

void
storeFsSetup_ufs(storefs_entry_t * storefs)
{
    assert(!ufs_initialised);
    storefs->donefunc = storeUfsDirDone;
    storefs->newfunc = storeUfsNew;
    ufs_initialised = 1;
}

void
UFSSwapDir::dumpEntry(StoreEntry &e) const
{
    debug(47, 0) ("UFSSwapDir::dumpEntry: FILENO %08X\n", e.swap_filen);
    debug(47, 0) ("UFSSwapDir::dumpEntry: PATH %s\n",
	fullPath(e.swap_filen, NULL));
    storeEntryDump(&e, 0);
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
    if (stat(fullPath(e.swap_filen, NULL), &sb) < 0) {
	debug(47, 0) ("UFSSwapDir::doubleCheck: MISSING SWAP FILE\n");
	dumpEntry(e);
	return true;
    }
    if ((off_t)e.swap_file_sz != sb.st_size) {
	debug(47, 0) ("UFSSwapDir::doubleCheck: SIZE MISMATCH\n");
	debug(47, 0) ("UFSSwapDir::doubleCheck: ENTRY SIZE: %ld, FILE SIZE: %ld\n",
	    (long int) e.swap_file_sz, (long int) sb.st_size);
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
}

void
UFSSwapDir::maintainfs()
{
    StoreEntry *e = NULL;
    int removed = 0;
    int max_scan;
    int max_remove;
    double f;
    RemovalPurgeWalker *walker;
    /* We can't delete objects while rebuilding swap */
    if (store_dirs_rebuilding) {
	return;
    } else {
	f = (double) (cur_size - low_size) / (max_size - low_size);
	f = f < 0.0 ? 0.0 : f > 1.0 ? 1.0 : f;
	max_scan = (int) (f * 400.0 + 100.0);
	max_remove = (int) (f * 70.0 + 10.0);
	/*
	 * This is kinda cheap, but so we need this priority hack?
	 */
    }
    debug(47, 3) ("storeMaintainSwapSpace: f=%f, max_scan=%d, max_remove=%d\n",
	f, max_scan, max_remove);
    walker = repl->PurgeInit(repl, max_scan);
    while (1) {
	if (cur_size < low_size)
	    break;
	if (removed >= max_remove)
	    break;
	e = walker->Next(walker);
	if (!e)
	    break;		/* no more objects */
	removed++;
	storeRelease(e);
    }
    walker->Done(walker);
    debug(47, (removed ? 2 : 3)) ("UFSSwapDir::maintainfs: %s removed %d/%d f=%.03f max_scan=%d\n",
	path, removed, max_remove, f, max_scan);
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
    debug(47, 3) ("UFSSwapDir::reference: referencing %p %d/%d\n", &e, e.swap_dirn,
	e.swap_filen);
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
    debug(47, 3) ("UFSSwapDir::dereference: referencing %p %d/%d\n", &e, e.swap_dirn,
	e.swap_filen);
    if (repl->Dereferenced)
	repl->Dereferenced(repl, &e, &e.repl);
}

StoreIOState::Pointer
UFSSwapDir::createStoreIO(StoreEntry &e, STFNCB * file_callback, STIOCB * callback, void *callback_data)
{
    return IO->create (this, &e, file_callback, callback, callback_data);
}

StoreIOState::Pointer
UFSSwapDir::openStoreIO(StoreEntry &e, STFNCB * file_callback, STIOCB * callback, void *callback_data)
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

/*
 * Initialise the asyncufs bitmap
 *
 * If there already is a bitmap, and the numobjects is larger than currently
 * configured, we allocate a new bitmap and 'grow' the old one into it.
 */
void
UFSSwapDir::initBitmap()
{
    if (map == NULL) {
	/* First time */
	map = file_map_create();
    } else if (map->max_n_files) {
	/* it grew, need to expand */
	/* XXX We don't need it anymore .. */
    }
    /* else it shrunk, and we leave the old one in place */
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
    if (0 == stat(path, &st)) {
	if (S_ISDIR(st.st_mode)) {
	    debug(47, should_exist ? 3 : 1) ("%s exists\n", path);
	} else {
	    fatalf("Swap directory %s is not a directory.", path);
	}
#ifdef _SQUID_MSWIN_
    } else if (0 == mkdir(path)) {
#else
    } else if (0 == mkdir(path, 0755)) {
#endif
	debug(47, should_exist ? 1 : 3) ("%s created\n", path);
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
    if (stat(path, &sb) < 0) {
	debug(47, 0) ("%s: %s\n", path, xstrerror());
	return false;
    }
    if (S_ISDIR(sb.st_mode) == 0) {
	debug(47, 0) ("%s is not a directory\n", path);
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
    int i, k;
    int should_exist;
    LOCAL_ARRAY(char, name, MAXPATHLEN);
    for (i = 0; i < l1; i++) {
	snprintf(name, MAXPATHLEN, "%s/%02X", path, i);
	if (createDirectory(name, 0))
	    should_exist = 0;
	else
	    should_exist = 1;
	debug(47, 1) ("Making directories in %s\n", name);
	for (k = 0; k < l2; k++) {
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
	debug(50, 1) ("%s: %s\n", logPath, xstrerror());
	fatal("commonUfsDirOpenSwapLog: Failed to open swap log.");
    }
    debug(50, 3) ("Cache Dir #%d log opened on FD %d\n", index, swaplog_fd);
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
    debug(47, 3) ("Cache Dir #%d log closed on FD %d\n",
	index, swaplog_fd);
    swaplog_fd = -1;
    NumberOfUFSDirs--;
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
    size_t swap_file_sz,
    time_t expires,
    time_t timestamp,
    time_t lastref,
    time_t lastmod,
    u_int32_t refcount,
    u_int16_t flags,
    int clean)
{
    StoreEntry *e = NULL;
    debug(47, 5) ("commonUfsAddDiskRestore: %s, fileno=%08X\n", storeKeyText(key), file_number);
    /* if you call this you'd better be sure file_number is not 
     * already in use! */
    e = new_StoreEntry(STORE_ENTRY_WITHOUT_MEMOBJ, NULL, NULL);
    e->store_status = STORE_OK;
    storeSetMemStatus(e, NOT_IN_MEMORY);
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
    storeHashInsert(e, key);	/* do it after we clear KEY_PRIVATE */
    replacementAdd (e);
    return e;
}

void
UFSSwapDir::rebuild()
{
    int clean = 0;
    int zero = 0;
    FILE *fp;
    EVH *func = NULL;
    RebuildState *rb = new RebuildState;
    rb->sd = this;
    rb->speed = opt_foreground_rebuild ? 1 << 30 : 50;
    /*
     * If the swap.state file exists in the cache_dir, then
     * we'll use commonUfsDirRebuildFromSwapLog(), otherwise we'll
     * use commonUfsDirRebuildFromDirectory() to open up each file
     * and suck in the meta data.
     */
    fp = openTmpSwapLog(&clean, &zero);
    if (fp == NULL || zero) {
	if (fp != NULL)
	    fclose(fp);
	func = RebuildState::RebuildFromDirectory;
    } else {
	func = RebuildState::RebuildFromSwapLog;
	rb->log = fp;
	rb->flags.clean = (unsigned int) clean;
    }
    if (!clean)
	rb->flags.need_to_validate = 1;
    debug(47, 1) ("Rebuilding storage in %s (%s)\n",
	path, clean ? "CLEAN" : "DIRTY");
    store_dirs_rebuilding++;
    eventAdd("storeRebuild", func, rb, 0.0, 1);
}

void
UFSSwapDir::closeTmpSwapLog()
{
    char *swaplog_path = xstrdup(logFile(NULL));
    char *new_path = xstrdup(logFile(".new"));
    int fd;
    file_close(swaplog_fd);
#if defined (_SQUID_OS2_) || defined (_SQUID_CYGWIN_) || defined(_SQUID_MSWIN_)
    if (::unlink(swaplog_path) < 0) {
	debug(50, 0) ("%s: %s\n", swaplog_path, xstrerror());
	fatal("commonUfsDirCloseTmpSwapLog: unlink failed");
    }
#endif
    if (xrename(new_path, swaplog_path) < 0) {
	fatal("commonUfsDirCloseTmpSwapLog: rename failed");
    }
    fd = file_open(swaplog_path, O_WRONLY | O_CREAT | O_BINARY);
    if (fd < 0) {
	debug(50, 1) ("%s: %s\n", swaplog_path, xstrerror());
	fatal("commonUfsDirCloseTmpSwapLog: Failed to open swap log.");
    }
    safe_free(swaplog_path);
    safe_free(new_path);
    swaplog_fd = fd;
    debug(47, 3) ("Cache Dir #%d log opened on FD %d\n", index, fd);
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
    if (stat(swaplog_path, &log_sb) < 0) {
	debug(47, 1) ("Cache Dir #%d: No log file\n", index);
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
	debug(50, 1) ("%s: %s\n", new_path, xstrerror());
	fatal("storeDirOpenTmpSwapLog: Failed to open swap log.");
    }
    swaplog_fd = fd;
    /* open a read-only stream of the old log */
    fp = fopen(swaplog_path, "rb");
    if (fp == NULL) {
	debug(50, 0) ("%s: %s\n", swaplog_path, xstrerror());
	fatal("Failed to open swap log for reading");
    }
    memset(&clean_sb, '\0', sizeof(struct stat));
    if (stat(clean_path, &clean_sb) < 0)
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

class UFSCleanLog : public SwapDir::CleanLog {
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

/*
 * Begin the process to write clean cache state.  For AUFS this means
 * opening some log files and allocating write buffers.  Return 0 if
 * we succeed, and assign the 'func' and 'data' return pointers.
 */

UFSCleanLog::UFSCleanLog(SwapDir *aSwapDir) : cur(NULL),newLog(NULL),cln(NULL),outbuf(NULL),
  outbuf_offset(0), fd(-1),walker(NULL), sd(aSwapDir)
{
}

int
UFSSwapDir::writeCleanStart()
{
    UFSCleanLog *state = new UFSCleanLog(this);
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
    state->walker = repl->WalkInit(repl);
    ::unlink(state->cln);
    debug(47, 3) ("storeDirWriteCleanLogs: opened %s, FD %d\n",
	state->newLog, state->fd);
#if HAVE_FCHMOD
    if (stat(state->cur, &sb) == 0)
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
    storeSwapLogData s;
    static size_t ss = sizeof(storeSwapLogData);
    memset(&s, '\0', ss);
    s.op = (char) SWAP_LOG_ADD;
    s.swap_filen = e.swap_filen;
    s.timestamp = e.timestamp;
    s.lastref = e.lastref;
    s.expires = e.expires;
    s.lastmod = e.lastmod;
    s.swap_file_sz = e.swap_file_sz;
    s.refcount = e.refcount;
    s.flags = e.flags;
    xmemcpy(&s.key, e.key, MD5_DIGEST_CHARS);
    UFSCleanLog *state = this;
    xmemcpy(state->outbuf + state->outbuf_offset, &s, ss);
    state->outbuf_offset += ss;
    /* buffered write */
    if (state->outbuf_offset + ss > CLEAN_BUF_SZ) {
	if (FD_WRITE_METHOD(state->fd, state->outbuf, state->outbuf_offset) < 0) {
	    debug(50, 0) ("storeDirWriteCleanLogs: %s: write: %s\n",
		state->newLog, xstrerror());
	    debug(50, 0) ("storeDirWriteCleanLogs: Current swap logfile not replaced.\n");
	    file_close(state->fd);
	    state->fd = -1;
	    unlink(state->newLog);
	    delete state;
	    sd->cleanLog = NULL;
	    return;
	}
	state->outbuf_offset = 0;
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
	debug(50, 0) ("storeDirWriteCleanLogs: %s: write: %s\n",
	    state->newLog, xstrerror());
	debug(50, 0) ("storeDirWriteCleanLogs: Current swap logfile "
	    "not replaced.\n");
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
#if defined(_SQUID_OS2_) || defined (_SQUID_CYGWIN_) || defined(_SQUID_MSWIN_)
	file_close(state->fd);
	state->fd = -1;
	if (::unlink(state->cur) < 0)
	    debug(50, 0) ("storeDirWriteCleanLogs: unlinkd failed: %s, %s\n",
		xstrerror(), state->cur);
#endif
	xrename(state->newLog, state->cur);
    }
    /* touch a timestamp file if we're not still validating */
    if (store_dirs_rebuilding)
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

void
storeSwapLogDataFree(void *s)
{
    memFree(s, MEM_SWAP_LOG_DATA);
}

void
UFSSwapDir::logEntry(const StoreEntry & e, int op) const
{
    storeSwapLogData *s = (storeSwapLogData *)memAllocate(MEM_SWAP_LOG_DATA);
    s->op = (char) op;
    s->swap_filen = e.swap_filen;
    s->timestamp = e.timestamp;
    s->lastref = e.lastref;
    s->expires = e.expires;
    s->lastmod = e.lastmod;
    s->swap_file_sz = e.swap_file_sz;
    s->refcount = e.refcount;
    s->flags = e.flags;
    xmemcpy(s->key, e.key, MD5_DIGEST_CHARS);
    file_write(swaplog_fd,
	-1,
	s,
	sizeof(storeSwapLogData),
	NULL,
	NULL,
	(FREE *) storeSwapLogDataFree);
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
    DIR *dp = NULL;
    struct dirent *de = NULL;
    LOCAL_ARRAY(char, p1, MAXPATHLEN + 1);
    LOCAL_ARRAY(char, p2, MAXPATHLEN + 1);
#if USE_TRUNCATE
    struct stat sb;
#endif
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
    debug(36, 3) ("storeDirClean: Cleaning directory %s\n", p1);
    dp = opendir(p1);
    if (dp == NULL) {
	if (errno == ENOENT) {
	    debug(36, 0) ("storeDirClean: WARNING: Creating %s\n", p1);
#ifdef _SQUID_MSWIN_
	    if (mkdir(p1) == 0)
#else
	    if (mkdir(p1, 0777) == 0)
#endif
		return 0;
	}
	debug(50, 0) ("storeDirClean: %s: %s\n", p1, xstrerror());
	safeunlink(p1, 1);
	return 0;
    }
    while ((de = readdir(dp)) != NULL && k < 20) {
	if (sscanf(de->d_name, "%X", &swapfileno) != 1)
	    continue;
	fn = swapfileno;	/* XXX should remove this cruft ! */
	if (SD->validFileno(fn, 1))
	    if (SD->mapBitTest(fn))
		if (UFSSwapDir::FilenoBelongsHere(fn, D0, D1, D2))
		    continue;
#if USE_TRUNCATE
	if (!stat(de->d_name, &sb))
	    if (sb.st_size == 0)
		continue;
#endif
	files[k++] = swapfileno;
    }
    closedir(dp);
    if (k == 0)
	return 0;
    qsort(files, k, sizeof(int), rev_int_sort);
    if (k > 10)
	k = 10;
    for (n = 0; n < k; n++) {
	debug(36, 3) ("storeDirClean: Cleaning file %08X\n", files[n]);
	snprintf(p2, MAXPATHLEN + 1, "%s/%08X", p1, files[n]);
#if USE_TRUNCATE
	truncate(p2, 0);
#else
	safeunlink(p2, 0);
#endif
	statCounter.swap.files_cleaned++;
    }
    debug(36, 3) ("Cleaned %d unused files from %s\n", k, p1);
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
	    sd = INDEXSD(i);
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
    if (0 == store_dirs_rebuilding) {
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
    assert (UFSSwapDir::IsUFSDir (INDEXSD(F0)));
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
    debug(79, 3) ("UFSSwapDir::unlinkFile: unlinking fileno %08X\n", f);
    /* commonUfsDirMapBitReset(this, f); */
    unlinkFile(fullPath(f, NULL));
}

/*
 * Add and remove the given StoreEntry from the replacement policy in
 * use.
 */

void
UFSSwapDir::replacementAdd(StoreEntry * e)
{
    debug(47, 4) ("UFSSwapDir::replacementAdd: added node %p to dir %d\n", e,
	index);
    repl->Add(repl, e, &e->repl);
}


void
UFSSwapDir::replacementRemove(StoreEntry * e)
{
    SwapDir *SD;
    if (e->swap_dirn < 0)
	return;
    SD = INDEXSD(e->swap_dirn);
    assert (dynamic_cast<UFSSwapDir *>(SD) == this);
    debug(47, 4) ("UFSSwapDir::replacementRemove: remove node %p from dir %d\n", e,
	index);
    repl->Remove(repl, e, &e->repl);
}

void
UFSSwapDir::dump(StoreEntry & entry) const
{
    storeAppendPrintf(&entry, " %d %d %d",
	max_size >> 10,
	l1,
	l2);
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
