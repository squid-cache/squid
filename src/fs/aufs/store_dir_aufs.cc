
/*
 * $Id: store_dir_aufs.cc,v 1.45 2002/05/19 16:40:56 hno Exp $
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

#include "store_asyncufs.h"

#define DefaultLevelOneDirs     16
#define DefaultLevelTwoDirs     256
#define STORE_META_BUFSZ 4096

typedef struct _RebuildState RebuildState;
struct _RebuildState {
    SwapDir *sd;
    int n_read;
    FILE *log;
    int speed;
    int curlvl1;
    int curlvl2;
    struct {
	unsigned int need_to_validate:1;
	unsigned int clean:1;
	unsigned int init:1;
    } flags;
    int done;
    int in_dir;
    int fn;
    struct dirent *entry;
    DIR *td;
    char fullpath[SQUID_MAXPATHLEN];
    char fullfilename[SQUID_MAXPATHLEN];
    struct _store_rebuild_data counts;
};

static int n_asyncufs_dirs = 0;
static int *asyncufs_dir_index = NULL;
MemPool *squidaio_state_pool = NULL;
MemPool *aufs_qread_pool = NULL;
MemPool *aufs_qwrite_pool = NULL;
static int asyncufs_initialised = 0;

static char *storeAufsDirSwapSubDir(SwapDir *, int subdirn);
static int storeAufsDirCreateDirectory(const char *path, int);
static int storeAufsDirVerifyCacheDirs(SwapDir *);
static int storeAufsDirVerifyDirectory(const char *path);
static void storeAufsDirCreateSwapSubDirs(SwapDir *);
static char *storeAufsDirSwapLogFile(SwapDir *, const char *);
static EVH storeAufsDirRebuildFromDirectory;
static EVH storeAufsDirRebuildFromSwapLog;
static int storeAufsDirGetNextFile(RebuildState *, sfileno *, int *size);
static StoreEntry *storeAufsDirAddDiskRestore(SwapDir * SD, const cache_key * key,
    sfileno file_number,
    size_t swap_file_sz,
    time_t expires,
    time_t timestamp,
    time_t lastref,
    time_t lastmod,
    u_num32 refcount,
    u_short flags,
    int clean);
static void storeAufsDirRebuild(SwapDir * sd);
static void storeAufsDirCloseTmpSwapLog(SwapDir * sd);
static FILE *storeAufsDirOpenTmpSwapLog(SwapDir *, int *, int *);
static STLOGOPEN storeAufsDirOpenSwapLog;
static STINIT storeAufsDirInit;
static STFREE storeAufsDirFree;
static STLOGCLEANSTART storeAufsDirWriteCleanStart;
static STLOGCLEANNEXTENTRY storeAufsDirCleanLogNextEntry;
static STLOGCLEANWRITE storeAufsDirWriteCleanEntry;
static STLOGCLEANDONE storeAufsDirWriteCleanDone;
static STLOGCLOSE storeAufsDirCloseSwapLog;
static STLOGWRITE storeAufsDirSwapLog;
static STNEWFS storeAufsDirNewfs;
static STDUMP storeAufsDirDump;
static STMAINTAINFS storeAufsDirMaintain;
static STCHECKOBJ storeAufsDirCheckObj;
static STREFOBJ storeAufsDirRefObj;
static STUNREFOBJ storeAufsDirUnrefObj;
static QS rev_int_sort;
static int storeAufsDirClean(int swap_index);
static EVH storeAufsDirCleanEvent;
static int storeAufsDirIs(SwapDir * sd);
static int storeAufsFilenoBelongsHere(int fn, int F0, int F1, int F2);
static int storeAufsCleanupDoubleCheck(SwapDir *, StoreEntry *);
static void storeAufsDirStats(SwapDir *, StoreEntry *);
static void storeAufsDirInitBitmap(SwapDir *);
static int storeAufsDirValidFileno(SwapDir *, sfileno, int);

/* The MAIN externally visible function */
STSETUP storeFsSetup_aufs;

/*
 * These functions were ripped straight out of the heart of store_dir.c.
 * They assume that the given filenum is on a asyncufs partiton, which may or
 * may not be true.. 
 * XXX this evilness should be tidied up at a later date!
 */

static int
storeAufsDirMapBitTest(SwapDir * SD, sfileno filn)
{
    squidaioinfo_t *aioinfo;
    aioinfo = (squidaioinfo_t *) SD->fsdata;
    return file_map_bit_test(aioinfo->map, filn);
}

static void
storeAufsDirMapBitSet(SwapDir * SD, sfileno filn)
{
    squidaioinfo_t *aioinfo;
    aioinfo = (squidaioinfo_t *) SD->fsdata;
    file_map_bit_set(aioinfo->map, filn);
}

void
storeAufsDirMapBitReset(SwapDir * SD, sfileno filn)
{
    squidaioinfo_t *aioinfo;
    aioinfo = (squidaioinfo_t *) SD->fsdata;
    /*
     * We have to test the bit before calling file_map_bit_reset.
     * file_map_bit_reset doesn't do bounds checking.  It assumes
     * filn is a valid file number, but it might not be because
     * the map is dynamic in size.  Also clearing an already clear
     * bit puts the map counter of-of-whack.
     */
    if (file_map_bit_test(aioinfo->map, filn))
	file_map_bit_reset(aioinfo->map, filn);
}

int
storeAufsDirMapBitAllocate(SwapDir * SD)
{
    squidaioinfo_t *aioinfo = (squidaioinfo_t *) SD->fsdata;
    int fn;
    fn = file_map_allocate(aioinfo->map, aioinfo->suggest);
    file_map_bit_set(aioinfo->map, fn);
    aioinfo->suggest = fn + 1;
    return fn;
}

/*
 * Initialise the asyncufs bitmap
 *
 * If there already is a bitmap, and the numobjects is larger than currently
 * configured, we allocate a new bitmap and 'grow' the old one into it.
 */
static void
storeAufsDirInitBitmap(SwapDir * sd)
{
    squidaioinfo_t *aioinfo = (squidaioinfo_t *) sd->fsdata;

    if (aioinfo->map == NULL) {
	/* First time */
	aioinfo->map = file_map_create();
    } else if (aioinfo->map->max_n_files) {
	/* it grew, need to expand */
	/* XXX We don't need it anymore .. */
    }
    /* else it shrunk, and we leave the old one in place */
}

static char *
storeAufsDirSwapSubDir(SwapDir * sd, int subdirn)
{
    squidaioinfo_t *aioinfo = (squidaioinfo_t *) sd->fsdata;

    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    assert(0 <= subdirn && subdirn < aioinfo->l1);
    snprintf(fullfilename, SQUID_MAXPATHLEN, "%s/%02X", sd->path, subdirn);
    return fullfilename;
}

static int
storeAufsDirCreateDirectory(const char *path, int should_exist)
{
    int created = 0;
    struct stat st;
    getCurrentTime();
    if (0 == stat(path, &st)) {
	if (S_ISDIR(st.st_mode)) {
	    debug(20, should_exist ? 3 : 1) ("%s exists\n", path);
	} else {
	    fatalf("Swap directory %s is not a directory.", path);
	}
    } else if (0 == mkdir(path, 0755)) {
	debug(20, should_exist ? 1 : 3) ("%s created\n", path);
	created = 1;
    } else {
	fatalf("Failed to make swap directory %s: %s",
	    path, xstrerror());
    }
    return created;
}

static int
storeAufsDirVerifyDirectory(const char *path)
{
    struct stat sb;
    if (stat(path, &sb) < 0) {
	debug(20, 0) ("%s: %s\n", path, xstrerror());
	return -1;
    }
    if (S_ISDIR(sb.st_mode) == 0) {
	debug(20, 0) ("%s is not a directory\n", path);
	return -1;
    }
    return 0;
}

/*
 * This function is called by storeAufsDirInit().  If this returns < 0,
 * then Squid exits, complains about swap directories not
 * existing, and instructs the admin to run 'squid -z'
 */
static int
storeAufsDirVerifyCacheDirs(SwapDir * sd)
{
    squidaioinfo_t *aioinfo = (squidaioinfo_t *) sd->fsdata;
    int j;
    const char *path = sd->path;

    if (storeAufsDirVerifyDirectory(path) < 0)
	return -1;
    for (j = 0; j < aioinfo->l1; j++) {
	path = storeAufsDirSwapSubDir(sd, j);
	if (storeAufsDirVerifyDirectory(path) < 0)
	    return -1;
    }
    return 0;
}

static void
storeAufsDirCreateSwapSubDirs(SwapDir * sd)
{
    squidaioinfo_t *aioinfo = (squidaioinfo_t *) sd->fsdata;
    int i, k;
    int should_exist;
    LOCAL_ARRAY(char, name, MAXPATHLEN);
    for (i = 0; i < aioinfo->l1; i++) {
	snprintf(name, MAXPATHLEN, "%s/%02X", sd->path, i);
	if (storeAufsDirCreateDirectory(name, 0))
	    should_exist = 0;
	else
	    should_exist = 1;
	debug(47, 1) ("Making directories in %s\n", name);
	for (k = 0; k < aioinfo->l2; k++) {
	    snprintf(name, MAXPATHLEN, "%s/%02X/%02X", sd->path, i, k);
	    storeAufsDirCreateDirectory(name, should_exist);
	}
    }
}

static char *
storeAufsDirSwapLogFile(SwapDir * sd, const char *ext)
{
    LOCAL_ARRAY(char, path, SQUID_MAXPATHLEN);
    LOCAL_ARRAY(char, pathtmp, SQUID_MAXPATHLEN);
    LOCAL_ARRAY(char, digit, 32);
    char *pathtmp2;
    if (Config.Log.swap) {
	xstrncpy(pathtmp, sd->path, SQUID_MAXPATHLEN - 64);
	pathtmp2 = pathtmp;
	while ((pathtmp2 = strchr(pathtmp2, '/')) != NULL)
	    *pathtmp2 = '.';
	while (strlen(pathtmp) && pathtmp[strlen(pathtmp) - 1] == '.')
	    pathtmp[strlen(pathtmp) - 1] = '\0';
	for (pathtmp2 = pathtmp; *pathtmp2 == '.'; pathtmp2++);
	snprintf(path, SQUID_MAXPATHLEN - 64, Config.Log.swap, pathtmp2);
	if (strncmp(path, Config.Log.swap, SQUID_MAXPATHLEN - 64) == 0) {
	    strcat(path, ".");
	    snprintf(digit, 32, "%02d", sd->index);
	    strncat(path, digit, 3);
	}
    } else {
	xstrncpy(path, sd->path, SQUID_MAXPATHLEN - 64);
	strcat(path, "/swap.state");
    }
    if (ext)
	strncat(path, ext, 16);
    return path;
}

static void
storeAufsDirOpenSwapLog(SwapDir * sd)
{
    squidaioinfo_t *aioinfo = (squidaioinfo_t *) sd->fsdata;
    char *path;
    int fd;
    path = storeAufsDirSwapLogFile(sd, NULL);
    fd = file_open(path, O_WRONLY | O_CREAT | O_BINARY);
    if (fd < 0) {
	debug(50, 1) ("%s: %s\n", path, xstrerror());
	fatal("storeAufsDirOpenSwapLog: Failed to open swap log.");
    }
    debug(47, 3) ("Cache Dir #%d log opened on FD %d\n", sd->index, fd);
    aioinfo->swaplog_fd = fd;
    if (0 == n_asyncufs_dirs)
	assert(NULL == asyncufs_dir_index);
    n_asyncufs_dirs++;
    assert(n_asyncufs_dirs <= Config.cacheSwap.n_configured);
}

static void
storeAufsDirCloseSwapLog(SwapDir * sd)
{
    squidaioinfo_t *aioinfo = (squidaioinfo_t *) sd->fsdata;
    if (aioinfo->swaplog_fd < 0)	/* not open */
	return;
    file_close(aioinfo->swaplog_fd);
    debug(47, 3) ("Cache Dir #%d log closed on FD %d\n",
	sd->index, aioinfo->swaplog_fd);
    aioinfo->swaplog_fd = -1;
    n_asyncufs_dirs--;
    assert(n_asyncufs_dirs >= 0);
    if (0 == n_asyncufs_dirs)
	safe_free(asyncufs_dir_index);
}

static void
storeAufsDirInit(SwapDir * sd)
{
    static int started_clean_event = 0;
    static const char *errmsg =
    "\tFailed to verify one of the swap directories, Check cache.log\n"
    "\tfor details.  Run 'squid -z' to create swap directories\n"
    "\tif needed, or if running Squid for the first time.";
    storeAufsDirInitBitmap(sd);
    if (storeAufsDirVerifyCacheDirs(sd) < 0)
	fatal(errmsg);
    storeAufsDirOpenSwapLog(sd);
    storeAufsDirRebuild(sd);
    if (!started_clean_event) {
	eventAdd("storeDirClean", storeAufsDirCleanEvent, NULL, 15.0, 1);
	started_clean_event = 1;
    }
    (void) storeDirGetBlkSize(sd->path, &sd->fs.blksize);
}

static void
storeAufsDirRebuildFromDirectory(void *data)
{
    RebuildState *rb = data;
    SwapDir *SD = rb->sd;
    LOCAL_ARRAY(char, hdr_buf, SM_PAGE_SIZE);
    StoreEntry *e = NULL;
    StoreEntry tmpe;
    cache_key key[MD5_DIGEST_CHARS];
    sfileno filn = 0;
    int count;
    int size;
    struct stat sb;
    int swap_hdr_len;
    int fd = -1;
    tlv *tlv_list;
    tlv *t;
    assert(rb != NULL);
    debug(20, 3) ("storeAufsDirRebuildFromDirectory: DIR #%d\n", rb->sd->index);
    for (count = 0; count < rb->speed; count++) {
	assert(fd == -1);
	fd = storeAufsDirGetNextFile(rb, &filn, &size);
	if (fd == -2) {
	    debug(20, 1) ("Done scanning %s swaplog (%d entries)\n",
		rb->sd->path, rb->n_read);
	    store_dirs_rebuilding--;
	    storeAufsDirCloseTmpSwapLog(rb->sd);
	    storeRebuildComplete(&rb->counts);
	    cbdataFree(rb);
	    return;
	} else if (fd < 0) {
	    continue;
	}
	assert(fd > -1);
	/* lets get file stats here */
	if (fstat(fd, &sb) < 0) {
	    debug(20, 1) ("storeAufsDirRebuildFromDirectory: fstat(FD %d): %s\n",
		fd, xstrerror());
	    file_close(fd);
	    store_open_disk_fd--;
	    fd = -1;
	    continue;
	}
	if ((++rb->counts.scancount & 0xFFFF) == 0)
	    debug(20, 3) ("  %s %7d files opened so far.\n",
		rb->sd->path, rb->counts.scancount);
	debug(20, 9) ("file_in: fd=%d %08X\n", fd, filn);
	statCounter.syscalls.disk.reads++;
	if (read(fd, hdr_buf, SM_PAGE_SIZE) < 0) {
	    debug(20, 1) ("storeAufsDirRebuildFromDirectory: read(FD %d): %s\n",
		fd, xstrerror());
	    file_close(fd);
	    store_open_disk_fd--;
	    fd = -1;
	    continue;
	}
	file_close(fd);
	store_open_disk_fd--;
	fd = -1;
	swap_hdr_len = 0;
#if USE_TRUNCATE
	if (sb.st_size == 0)
	    continue;
#endif
	tlv_list = storeSwapMetaUnpack(hdr_buf, &swap_hdr_len);
	if (tlv_list == NULL) {
	    debug(20, 1) ("storeAufsDirRebuildFromDirectory: failed to get meta data\n");
	    /* XXX shouldn't this be a call to storeAufsUnlink ? */
	    storeAufsDirUnlinkFile(SD, filn);
	    continue;
	}
	debug(20, 3) ("storeAufsDirRebuildFromDirectory: successful swap meta unpacking\n");
	memset(key, '\0', MD5_DIGEST_CHARS);
	memset(&tmpe, '\0', sizeof(StoreEntry));
	for (t = tlv_list; t; t = t->next) {
	    switch (t->type) {
	    case STORE_META_KEY:
		assert(t->length == MD5_DIGEST_CHARS);
		xmemcpy(key, t->value, MD5_DIGEST_CHARS);
		break;
	    case STORE_META_STD:
		assert(t->length == STORE_HDR_METASIZE);
		xmemcpy(&tmpe.timestamp, t->value, STORE_HDR_METASIZE);
		break;
	    default:
		break;
	    }
	}
	storeSwapTLVFree(tlv_list);
	tlv_list = NULL;
	if (storeKeyNull(key)) {
	    debug(20, 1) ("storeAufsDirRebuildFromDirectory: NULL key\n");
	    storeAufsDirUnlinkFile(SD, filn);
	    continue;
	}
	tmpe.hash.key = key;
	/* check sizes */
	if (tmpe.swap_file_sz == 0) {
	    tmpe.swap_file_sz = sb.st_size;
	} else if (tmpe.swap_file_sz == sb.st_size - swap_hdr_len) {
	    tmpe.swap_file_sz = sb.st_size;
	} else if (tmpe.swap_file_sz != sb.st_size) {
	    debug(20, 1) ("storeAufsDirRebuildFromDirectory: SIZE MISMATCH %ld!=%ld\n",
		(long int) tmpe.swap_file_sz, (long int) sb.st_size);
	    storeAufsDirUnlinkFile(SD, filn);
	    continue;
	}
	if (EBIT_TEST(tmpe.flags, KEY_PRIVATE)) {
	    storeAufsDirUnlinkFile(SD, filn);
	    rb->counts.badflags++;
	    continue;
	}
	e = storeGet(key);
	if (e && e->lastref >= tmpe.lastref) {
	    /* key already exists, current entry is newer */
	    /* keep old, ignore new */
	    rb->counts.dupcount++;
	    continue;
	} else if (NULL != e) {
	    /* URL already exists, this swapfile not being used */
	    /* junk old, load new */
	    storeRelease(e);	/* release old entry */
	    rb->counts.dupcount++;
	}
	rb->counts.objcount++;
	storeEntryDump(&tmpe, 5);
	e = storeAufsDirAddDiskRestore(SD, key,
	    filn,
	    tmpe.swap_file_sz,
	    tmpe.expires,
	    tmpe.timestamp,
	    tmpe.lastref,
	    tmpe.lastmod,
	    tmpe.refcount,	/* refcount */
	    tmpe.flags,		/* flags */
	    (int) rb->flags.clean);
	storeDirSwapLog(e, SWAP_LOG_ADD);
    }
    eventAdd("storeRebuild", storeAufsDirRebuildFromDirectory, rb, 0.0, 1);
}

static void
storeAufsDirRebuildFromSwapLog(void *data)
{
    RebuildState *rb = data;
    SwapDir *SD = rb->sd;
    StoreEntry *e = NULL;
    storeSwapLogData s;
    size_t ss = sizeof(storeSwapLogData);
    int count;
    int used;			/* is swapfile already in use? */
    int disk_entry_newer;	/* is the log entry newer than current entry? */
    double x;
    assert(rb != NULL);
    /* load a number of objects per invocation */
    for (count = 0; count < rb->speed; count++) {
	if (fread(&s, ss, 1, rb->log) != 1) {
	    debug(20, 1) ("Done reading %s swaplog (%d entries)\n",
		rb->sd->path, rb->n_read);
	    fclose(rb->log);
	    rb->log = NULL;
	    store_dirs_rebuilding--;
	    storeAufsDirCloseTmpSwapLog(rb->sd);
	    storeRebuildComplete(&rb->counts);
	    cbdataFree(rb);
	    return;
	}
	rb->n_read++;
	if (s.op <= SWAP_LOG_NOP)
	    continue;
	if (s.op >= SWAP_LOG_MAX)
	    continue;
	/*
	 * BC: during 2.4 development, we changed the way swap file
	 * numbers are assigned and stored.  The high 16 bits used
	 * to encode the SD index number.  There used to be a call
	 * to storeDirProperFileno here that re-assigned the index 
	 * bits.  Now, for backwards compatibility, we just need
	 * to mask it off.
	 */
	s.swap_filen &= 0x00FFFFFF;
	debug(20, 3) ("storeAufsDirRebuildFromSwapLog: %s %s %08X\n",
	    swap_log_op_str[(int) s.op],
	    storeKeyText(s.key),
	    s.swap_filen);
	if (s.op == SWAP_LOG_ADD) {
	    (void) 0;
	} else if (s.op == SWAP_LOG_DEL) {
	    if ((e = storeGet(s.key)) != NULL) {
		/*
		 * Make sure we don't unlink the file, it might be
		 * in use by a subsequent entry.  Also note that
		 * we don't have to subtract from store_swap_size
		 * because adding to store_swap_size happens in
		 * the cleanup procedure.
		 */
		storeExpireNow(e);
		storeReleaseRequest(e);
		if (e->swap_filen > -1) {
		    storeAufsDirReplRemove(e);
		    storeAufsDirMapBitReset(SD, e->swap_filen);
		    e->swap_filen = -1;
		    e->swap_dirn = -1;
		}
		storeRelease(e);
		rb->counts.objcount--;
		rb->counts.cancelcount++;
	    }
	    continue;
	} else {
	    x = log(++rb->counts.bad_log_op) / log(10.0);
	    if (0.0 == x - (double) (int) x)
		debug(20, 1) ("WARNING: %d invalid swap log entries found\n",
		    rb->counts.bad_log_op);
	    rb->counts.invalid++;
	    continue;
	}
	if ((++rb->counts.scancount & 0xFFF) == 0) {
	    struct stat sb;
	    if (0 == fstat(fileno(rb->log), &sb))
		storeRebuildProgress(SD->index,
		    (int) sb.st_size / ss, rb->n_read);
	}
	if (!storeAufsDirValidFileno(SD, s.swap_filen, 0)) {
	    rb->counts.invalid++;
	    continue;
	}
	if (EBIT_TEST(s.flags, KEY_PRIVATE)) {
	    rb->counts.badflags++;
	    continue;
	}
	e = storeGet(s.key);
	used = storeAufsDirMapBitTest(SD, s.swap_filen);
	/* If this URL already exists in the cache, does the swap log
	 * appear to have a newer entry?  Compare 'lastref' from the
	 * swap log to e->lastref. */
	disk_entry_newer = e ? (s.lastref > e->lastref ? 1 : 0) : 0;
	if (used && !disk_entry_newer) {
	    /* log entry is old, ignore it */
	    rb->counts.clashcount++;
	    continue;
	} else if (used && e && e->swap_filen == s.swap_filen && e->swap_dirn == SD->index) {
	    /* swapfile taken, same URL, newer, update meta */
	    if (e->store_status == STORE_OK) {
		e->lastref = s.timestamp;
		e->timestamp = s.timestamp;
		e->expires = s.expires;
		e->lastmod = s.lastmod;
		e->flags = s.flags;
		e->refcount += s.refcount;
		storeAufsDirUnrefObj(SD, e);
	    } else {
		debug_trap("storeAufsDirRebuildFromSwapLog: bad condition");
		debug(20, 1) ("\tSee %s:%d\n", __FILE__, __LINE__);
	    }
	    continue;
	} else if (used) {
	    /* swapfile in use, not by this URL, log entry is newer */
	    /* This is sorta bad: the log entry should NOT be newer at this
	     * point.  If the log is dirty, the filesize check should have
	     * caught this.  If the log is clean, there should never be a
	     * newer entry. */
	    debug(20, 1) ("WARNING: newer swaplog entry for dirno %d, fileno %08X\n",
		SD->index, s.swap_filen);
	    /* I'm tempted to remove the swapfile here just to be safe,
	     * but there is a bad race condition in the NOVM version if
	     * the swapfile has recently been opened for writing, but
	     * not yet opened for reading.  Because we can't map
	     * swapfiles back to StoreEntrys, we don't know the state
	     * of the entry using that file.  */
	    /* We'll assume the existing entry is valid, probably because
	     * were in a slow rebuild and the the swap file number got taken
	     * and the validation procedure hasn't run. */
	    assert(rb->flags.need_to_validate);
	    rb->counts.clashcount++;
	    continue;
	} else if (e && !disk_entry_newer) {
	    /* key already exists, current entry is newer */
	    /* keep old, ignore new */
	    rb->counts.dupcount++;
	    continue;
	} else if (e) {
	    /* key already exists, this swapfile not being used */
	    /* junk old, load new */
	    storeExpireNow(e);
	    storeReleaseRequest(e);
	    if (e->swap_filen > -1) {
		storeAufsDirReplRemove(e);
		/* Make sure we don't actually unlink the file */
		storeAufsDirMapBitReset(SD, e->swap_filen);
		e->swap_filen = -1;
		e->swap_dirn = -1;
	    }
	    storeRelease(e);
	    rb->counts.dupcount++;
	} else {
	    /* URL doesnt exist, swapfile not in use */
	    /* load new */
	    (void) 0;
	}
	/* update store_swap_size */
	rb->counts.objcount++;
	e = storeAufsDirAddDiskRestore(SD, s.key,
	    s.swap_filen,
	    s.swap_file_sz,
	    s.expires,
	    s.timestamp,
	    s.lastref,
	    s.lastmod,
	    s.refcount,
	    s.flags,
	    (int) rb->flags.clean);
	storeDirSwapLog(e, SWAP_LOG_ADD);
    }
    eventAdd("storeRebuild", storeAufsDirRebuildFromSwapLog, rb, 0.0, 1);
}

static int
storeAufsDirGetNextFile(RebuildState * rb, sfileno * filn_p, int *size)
{
    SwapDir *SD = rb->sd;
    squidaioinfo_t *aioinfo = (squidaioinfo_t *) SD->fsdata;
    int fd = -1;
    int used = 0;
    int dirs_opened = 0;
    debug(20, 3) ("storeAufsDirGetNextFile: flag=%d, %d: /%02X/%02X\n",
	rb->flags.init,
	rb->sd->index,
	rb->curlvl1,
	rb->curlvl2);
    if (rb->done)
	return -2;
    while (fd < 0 && rb->done == 0) {
	fd = -1;
	if (0 == rb->flags.init) {	/* initialize, open first file */
	    rb->done = 0;
	    rb->curlvl1 = 0;
	    rb->curlvl2 = 0;
	    rb->in_dir = 0;
	    rb->flags.init = 1;
	    assert(Config.cacheSwap.n_configured > 0);
	}
	if (0 == rb->in_dir) {	/* we need to read in a new directory */
	    snprintf(rb->fullpath, SQUID_MAXPATHLEN, "%s/%02X/%02X",
		rb->sd->path,
		rb->curlvl1, rb->curlvl2);
	    if (dirs_opened)
		return -1;
	    rb->td = opendir(rb->fullpath);
	    dirs_opened++;
	    if (rb->td == NULL) {
		debug(50, 1) ("storeAufsDirGetNextFile: opendir: %s: %s\n",
		    rb->fullpath, xstrerror());
	    } else {
		rb->entry = readdir(rb->td);	/* skip . and .. */
		rb->entry = readdir(rb->td);
		if (rb->entry == NULL && errno == ENOENT)
		    debug(20, 1) ("storeAufsDirGetNextFile: directory does not exist!.\n");
		debug(20, 3) ("storeAufsDirGetNextFile: Directory %s\n", rb->fullpath);
	    }
	}
	if (rb->td != NULL && (rb->entry = readdir(rb->td)) != NULL) {
	    rb->in_dir++;
	    if (sscanf(rb->entry->d_name, "%x", &rb->fn) != 1) {
		debug(20, 3) ("storeAufsDirGetNextFile: invalid %s\n",
		    rb->entry->d_name);
		continue;
	    }
	    if (!storeAufsFilenoBelongsHere(rb->fn, rb->sd->index, rb->curlvl1, rb->curlvl2)) {
		debug(20, 3) ("storeAufsDirGetNextFile: %08X does not belong in %d/%d/%d\n",
		    rb->fn, rb->sd->index, rb->curlvl1, rb->curlvl2);
		continue;
	    }
	    used = storeAufsDirMapBitTest(SD, rb->fn);
	    if (used) {
		debug(20, 3) ("storeAufsDirGetNextFile: Locked, continuing with next.\n");
		continue;
	    }
	    snprintf(rb->fullfilename, SQUID_MAXPATHLEN, "%s/%s",
		rb->fullpath, rb->entry->d_name);
	    debug(20, 3) ("storeAufsDirGetNextFile: Opening %s\n", rb->fullfilename);
	    fd = file_open(rb->fullfilename, O_RDONLY | O_BINARY);
	    if (fd < 0)
		debug(50, 1) ("storeAufsDirGetNextFile: %s: %s\n", rb->fullfilename, xstrerror());
	    else
		store_open_disk_fd++;
	    continue;
	}
	if (rb->td != NULL)
	    closedir(rb->td);
	rb->td = NULL;
	rb->in_dir = 0;
	if (++rb->curlvl2 < aioinfo->l2)
	    continue;
	rb->curlvl2 = 0;
	if (++rb->curlvl1 < aioinfo->l1)
	    continue;
	rb->curlvl1 = 0;
	rb->done = 1;
    }
    *filn_p = rb->fn;
    return fd;
}

/* Add a new object to the cache with empty memory copy and pointer to disk
 * use to rebuild store from disk. */
static StoreEntry *
storeAufsDirAddDiskRestore(SwapDir * SD, const cache_key * key,
    sfileno file_number,
    size_t swap_file_sz,
    time_t expires,
    time_t timestamp,
    time_t lastref,
    time_t lastmod,
    u_num32 refcount,
    u_short flags,
    int clean)
{
    StoreEntry *e = NULL;
    debug(20, 5) ("storeAufsAddDiskRestore: %s, fileno=%08X\n", storeKeyText(key), file_number);
    /* if you call this you'd better be sure file_number is not 
     * already in use! */
    e = new_StoreEntry(STORE_ENTRY_WITHOUT_MEMOBJ, NULL, NULL);
    e->store_status = STORE_OK;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    e->swap_status = SWAPOUT_DONE;
    e->swap_filen = file_number;
    e->swap_dirn = SD->index;
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
    storeAufsDirMapBitSet(SD, e->swap_filen);
    storeHashInsert(e, key);	/* do it after we clear KEY_PRIVATE */
    storeAufsDirReplAdd(SD, e);
    return e;
}

CBDATA_TYPE(RebuildState);

static void
storeAufsDirRebuild(SwapDir * sd)
{
    RebuildState *rb;
    int clean = 0;
    int zero = 0;
    FILE *fp;
    EVH *func = NULL;
    CBDATA_INIT_TYPE(RebuildState);
    rb = cbdataAlloc(RebuildState);
    rb->sd = sd;
    rb->speed = opt_foreground_rebuild ? 1 << 30 : 50;
    /*
     * If the swap.state file exists in the cache_dir, then
     * we'll use storeAufsDirRebuildFromSwapLog(), otherwise we'll
     * use storeAufsDirRebuildFromDirectory() to open up each file
     * and suck in the meta data.
     */
    fp = storeAufsDirOpenTmpSwapLog(sd, &clean, &zero);
    if (fp == NULL || zero) {
	if (fp != NULL)
	    fclose(fp);
	func = storeAufsDirRebuildFromDirectory;
    } else {
	func = storeAufsDirRebuildFromSwapLog;
	rb->log = fp;
	rb->flags.clean = (unsigned int) clean;
    }
    if (!clean)
	rb->flags.need_to_validate = 1;
    debug(20, 1) ("Rebuilding storage in %s (%s)\n",
	sd->path, clean ? "CLEAN" : "DIRTY");
    store_dirs_rebuilding++;
    eventAdd("storeRebuild", func, rb, 0.0, 1);
}

static void
storeAufsDirCloseTmpSwapLog(SwapDir * sd)
{
    squidaioinfo_t *aioinfo = (squidaioinfo_t *) sd->fsdata;
    char *swaplog_path = xstrdup(storeAufsDirSwapLogFile(sd, NULL));
    char *new_path = xstrdup(storeAufsDirSwapLogFile(sd, ".new"));
    int fd;
    file_close(aioinfo->swaplog_fd);
#if defined (_SQUID_OS2_) || defined (_SQUID_CYGWIN_)
    if (unlink(swaplog_path) < 0) {
	debug(50, 0) ("%s: %s\n", swaplog_path, xstrerror());
	fatal("storeAufsDirCloseTmpSwapLog: unlink failed");
    }
#endif
    if (xrename(new_path, swaplog_path) < 0) {
	fatal("storeAufsDirCloseTmpSwapLog: rename failed");
    }
    fd = file_open(swaplog_path, O_WRONLY | O_CREAT | O_BINARY);
    if (fd < 0) {
	debug(50, 1) ("%s: %s\n", swaplog_path, xstrerror());
	fatal("storeAufsDirCloseTmpSwapLog: Failed to open swap log.");
    }
    safe_free(swaplog_path);
    safe_free(new_path);
    aioinfo->swaplog_fd = fd;
    debug(47, 3) ("Cache Dir #%d log opened on FD %d\n", sd->index, fd);
}

static FILE *
storeAufsDirOpenTmpSwapLog(SwapDir * sd, int *clean_flag, int *zero_flag)
{
    squidaioinfo_t *aioinfo = (squidaioinfo_t *) sd->fsdata;
    char *swaplog_path = xstrdup(storeAufsDirSwapLogFile(sd, NULL));
    char *clean_path = xstrdup(storeAufsDirSwapLogFile(sd, ".last-clean"));
    char *new_path = xstrdup(storeAufsDirSwapLogFile(sd, ".new"));
    struct stat log_sb;
    struct stat clean_sb;
    FILE *fp;
    int fd;
    if (stat(swaplog_path, &log_sb) < 0) {
	debug(47, 1) ("Cache Dir #%d: No log file\n", sd->index);
	safe_free(swaplog_path);
	safe_free(clean_path);
	safe_free(new_path);
	return NULL;
    }
    *zero_flag = log_sb.st_size == 0 ? 1 : 0;
    /* close the existing write-only FD */
    if (aioinfo->swaplog_fd >= 0)
	file_close(aioinfo->swaplog_fd);
    /* open a write-only FD for the new log */
    fd = file_open(new_path, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) {
	debug(50, 1) ("%s: %s\n", new_path, xstrerror());
	fatal("storeDirOpenTmpSwapLog: Failed to open swap log.");
    }
    aioinfo->swaplog_fd = fd;
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

struct _clean_state {
    char *cur;
    char *new;
    char *cln;
    char *outbuf;
    off_t outbuf_offset;
    int fd;
    RemovalPolicyWalker *walker;
};

#define CLEAN_BUF_SZ 16384
/*
 * Begin the process to write clean cache state.  For AUFS this means
 * opening some log files and allocating write buffers.  Return 0 if
 * we succeed, and assign the 'func' and 'data' return pointers.
 */
static int
storeAufsDirWriteCleanStart(SwapDir * sd)
{
    struct _clean_state *state = xcalloc(1, sizeof(*state));
#if HAVE_FCHMOD
    struct stat sb;
#endif
    sd->log.clean.write = NULL;
    sd->log.clean.state = NULL;
    state->new = xstrdup(storeAufsDirSwapLogFile(sd, ".clean"));
    state->fd = file_open(state->new, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY);
    if (state->fd < 0) {
	xfree(state->new);
	xfree(state);
	return -1;
    }
    state->cur = xstrdup(storeAufsDirSwapLogFile(sd, NULL));
    state->cln = xstrdup(storeAufsDirSwapLogFile(sd, ".last-clean"));
    state->outbuf = xcalloc(CLEAN_BUF_SZ, 1);
    state->outbuf_offset = 0;
    state->walker = sd->repl->WalkInit(sd->repl);
    unlink(state->cln);
    debug(20, 3) ("storeDirWriteCleanLogs: opened %s, FD %d\n",
	state->new, state->fd);
#if HAVE_FCHMOD
    if (stat(state->cur, &sb) == 0)
	fchmod(state->fd, sb.st_mode);
#endif
    sd->log.clean.write = storeAufsDirWriteCleanEntry;
    sd->log.clean.state = state;
    return 0;
}

/*
 * Get the next entry that is a candidate for clean log writing
 */
const StoreEntry *
storeAufsDirCleanLogNextEntry(SwapDir * sd)
{
    const StoreEntry *entry = NULL;
    struct _clean_state *state = sd->log.clean.state;
    if (state->walker)
	entry = state->walker->Next(state->walker);
    return entry;
}

/*
 * "write" an entry to the clean log file.
 */
static void
storeAufsDirWriteCleanEntry(SwapDir * sd, const StoreEntry * e)
{
    storeSwapLogData s;
    static size_t ss = sizeof(storeSwapLogData);
    struct _clean_state *state = sd->log.clean.state;
    memset(&s, '\0', ss);
    s.op = (char) SWAP_LOG_ADD;
    s.swap_filen = e->swap_filen;
    s.timestamp = e->timestamp;
    s.lastref = e->lastref;
    s.expires = e->expires;
    s.lastmod = e->lastmod;
    s.swap_file_sz = e->swap_file_sz;
    s.refcount = e->refcount;
    s.flags = e->flags;
    xmemcpy(&s.key, e->hash.key, MD5_DIGEST_CHARS);
    xmemcpy(state->outbuf + state->outbuf_offset, &s, ss);
    state->outbuf_offset += ss;
    /* buffered write */
    if (state->outbuf_offset + ss > CLEAN_BUF_SZ) {
	if (write(state->fd, state->outbuf, state->outbuf_offset) < 0) {
	    debug(50, 0) ("storeDirWriteCleanLogs: %s: write: %s\n",
		state->new, xstrerror());
	    debug(20, 0) ("storeDirWriteCleanLogs: Current swap logfile not replaced.\n");
	    file_close(state->fd);
	    state->fd = -1;
	    unlink(state->new);
	    safe_free(state);
	    sd->log.clean.state = NULL;
	    sd->log.clean.write = NULL;
	    return;
	}
	state->outbuf_offset = 0;
    }
}

static void
storeAufsDirWriteCleanDone(SwapDir * sd)
{
    int fd;
    struct _clean_state *state = sd->log.clean.state;
    if (NULL == state)
	return;
    if (state->fd < 0)
	return;
    state->walker->Done(state->walker);
    if (write(state->fd, state->outbuf, state->outbuf_offset) < 0) {
	debug(50, 0) ("storeDirWriteCleanLogs: %s: write: %s\n",
	    state->new, xstrerror());
	debug(20, 0) ("storeDirWriteCleanLogs: Current swap logfile "
	    "not replaced.\n");
	file_close(state->fd);
	state->fd = -1;
	unlink(state->new);
    }
    safe_free(state->outbuf);
    /*
     * You can't rename open files on Microsoft "operating systems"
     * so we have to close before renaming.
     */
    storeAufsDirCloseSwapLog(sd);
    /* save the fd value for a later test */
    fd = state->fd;
    /* rename */
    if (state->fd >= 0) {
#if defined(_SQUID_OS2_) || defined (_SQUID_CYGWIN_)
	file_close(state->fd);
	state->fd = -1;
	if (unlink(state->cur) < 0)
	    debug(50, 0) ("storeDirWriteCleanLogs: unlinkd failed: %s, %s\n",
		xstrerror(), state->cur);
#endif
	xrename(state->new, state->cur);
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
    safe_free(state->new);
    safe_free(state->cln);
    if (state->fd >= 0)
	file_close(state->fd);
    state->fd = -1;
    safe_free(state);
    sd->log.clean.state = NULL;
    sd->log.clean.write = NULL;
}

static void
storeSwapLogDataFree(void *s)
{
    memFree(s, MEM_SWAP_LOG_DATA);
}

static void
storeAufsDirSwapLog(const SwapDir * sd, const StoreEntry * e, int op)
{
    squidaioinfo_t *aioinfo = (squidaioinfo_t *) sd->fsdata;
    storeSwapLogData *s = memAllocate(MEM_SWAP_LOG_DATA);
    s->op = (char) op;
    s->swap_filen = e->swap_filen;
    s->timestamp = e->timestamp;
    s->lastref = e->lastref;
    s->expires = e->expires;
    s->lastmod = e->lastmod;
    s->swap_file_sz = e->swap_file_sz;
    s->refcount = e->refcount;
    s->flags = e->flags;
    xmemcpy(s->key, e->hash.key, MD5_DIGEST_CHARS);
    file_write(aioinfo->swaplog_fd,
	-1,
	s,
	sizeof(storeSwapLogData),
	NULL,
	NULL,
	(FREE *) storeSwapLogDataFree);
}

static void
storeAufsDirNewfs(SwapDir * sd)
{
    debug(47, 3) ("Creating swap space in %s\n", sd->path);
    storeAufsDirCreateDirectory(sd->path, 0);
    storeAufsDirCreateSwapSubDirs(sd);
}

static int
rev_int_sort(const void *A, const void *B)
{
    const int *i1 = A;
    const int *i2 = B;
    return *i2 - *i1;
}

static int
storeAufsDirClean(int swap_index)
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
    SwapDir *SD;
    squidaioinfo_t *aioinfo;
    N0 = n_asyncufs_dirs;
    D0 = asyncufs_dir_index[swap_index % N0];
    SD = &Config.cacheSwap.swapDirs[D0];
    aioinfo = (squidaioinfo_t *) SD->fsdata;
    N1 = aioinfo->l1;
    D1 = (swap_index / N0) % N1;
    N2 = aioinfo->l2;
    D2 = ((swap_index / N0) / N1) % N2;
    snprintf(p1, SQUID_MAXPATHLEN, "%s/%02X/%02X",
	Config.cacheSwap.swapDirs[D0].path, D1, D2);
    debug(36, 3) ("storeDirClean: Cleaning directory %s\n", p1);
    dp = opendir(p1);
    if (dp == NULL) {
	if (errno == ENOENT) {
	    debug(36, 0) ("storeDirClean: WARNING: Creating %s\n", p1);
	    if (mkdir(p1, 0777) == 0)
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
	if (storeAufsDirValidFileno(SD, fn, 1))
	    if (storeAufsDirMapBitTest(SD, fn))
		if (storeAufsFilenoBelongsHere(fn, D0, D1, D2))
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

static void
storeAufsDirCleanEvent(void *unused)
{
    static int swap_index = 0;
    int i;
    int j = 0;
    int n = 0;
    /*
     * Assert that there are AUFS cache_dirs configured, otherwise
     * we should never be called.
     */
    assert(n_asyncufs_dirs);
    if (NULL == asyncufs_dir_index) {
	SwapDir *sd;
	squidaioinfo_t *aioinfo;
	/*
	 * Initialize the little array that translates AUFS cache_dir
	 * number into the Config.cacheSwap.swapDirs array index.
	 */
	asyncufs_dir_index = xcalloc(n_asyncufs_dirs, sizeof(*asyncufs_dir_index));
	for (i = 0, n = 0; i < Config.cacheSwap.n_configured; i++) {
	    sd = &Config.cacheSwap.swapDirs[i];
	    if (!storeAufsDirIs(sd))
		continue;
	    asyncufs_dir_index[n++] = i;
	    aioinfo = (squidaioinfo_t *) sd->fsdata;
	    j += (aioinfo->l1 * aioinfo->l2);
	}
	assert(n == n_asyncufs_dirs);
	/*
	 * Start the storeAufsDirClean() swap_index with a random
	 * value.  j equals the total number of AUFS level 2
	 * swap directories
	 */
	swap_index = (int) (squid_random() % j);
    }
    if (0 == store_dirs_rebuilding) {
	n = storeAufsDirClean(swap_index);
	swap_index++;
    }
    eventAdd("storeDirClean", storeAufsDirCleanEvent, NULL,
	15.0 * exp(-0.25 * n), 1);
}

static int
storeAufsDirIs(SwapDir * sd)
{
    if (strncmp(sd->type, "aufs", 3) == 0)
	return 1;
    return 0;
}

/*
 * Does swapfile number 'fn' belong in cachedir #F0,
 * level1 dir #F1, level2 dir #F2?
 */
static int
storeAufsFilenoBelongsHere(int fn, int F0, int F1, int F2)
{
    int D1, D2;
    int L1, L2;
    int filn = fn;
    squidaioinfo_t *aioinfo;
    assert(F0 < Config.cacheSwap.n_configured);
    aioinfo = (squidaioinfo_t *) Config.cacheSwap.swapDirs[F0].fsdata;
    L1 = aioinfo->l1;
    L2 = aioinfo->l2;
    D1 = ((filn / L2) / L2) % L1;
    if (F1 != D1)
	return 0;
    D2 = (filn / L2) % L2;
    if (F2 != D2)
	return 0;
    return 1;
}

int
storeAufsDirValidFileno(SwapDir * SD, sfileno filn, int flag)
{
    squidaioinfo_t *aioinfo = (squidaioinfo_t *) SD->fsdata;
    if (filn < 0)
	return 0;
    /*
     * If flag is set it means out-of-range file number should
     * be considered invalid.
     */
    if (flag)
	if (filn > aioinfo->map->max_n_files)
	    return 0;
    return 1;
}

void
storeAufsDirMaintain(SwapDir * SD)
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
	f = (double) (SD->cur_size - SD->low_size) / (SD->max_size - SD->low_size);
	f = f < 0.0 ? 0.0 : f > 1.0 ? 1.0 : f;
	max_scan = (int) (f * 400.0 + 100.0);
	max_remove = (int) (f * 70.0 + 10.0);
	/*
	 * This is kinda cheap, but so we need this priority hack?
	 */
    }
    debug(20, 3) ("storeMaintainSwapSpace: f=%f, max_scan=%d, max_remove=%d\n",
	f, max_scan, max_remove);
    walker = SD->repl->PurgeInit(SD->repl, max_scan);
    while (1) {
	if (SD->cur_size < SD->low_size)
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
    debug(20, (removed ? 2 : 3)) ("storeUfsDirMaintain: %s removed %d/%d f=%.03f max_scan=%d\n",
	SD->path, removed, max_remove, f, max_scan);
}

/*
 * storeAufsDirCheckObj
 *
 * This routine is called by storeDirSelectSwapDir to see if the given
 * object is able to be stored on this filesystem. AUFS filesystems will
 * happily store anything as long as the LRU time isn't too small.
 */
int
storeAufsDirCheckObj(SwapDir * SD, const StoreEntry * e)
{
    int loadav;
    int ql;

#if OLD_UNUSED_CODE
    if (storeAufsDirExpiredReferenceAge(SD) < 300) {
	debug(20, 3) ("storeAufsDirCheckObj: NO: LRU Age = %d\n",
	    storeAufsDirExpiredReferenceAge(SD));
	/* store_check_cachable_hist.no.lru_age_too_low++; */
	return -1;
    }
#endif
    ql = aioQueueSize();
    if (ql == 0)
	loadav = 0;
    loadav = ql * 1000 / MAGIC1;
    debug(41, 9) ("storeAufsDirCheckObj: load=%d\n", loadav);
    return loadav;
}

/*
 * storeAufsDirRefObj
 *
 * This routine is called whenever an object is referenced, so we can
 * maintain replacement information within the storage fs.
 */
void
storeAufsDirRefObj(SwapDir * SD, StoreEntry * e)
{
    debug(1, 3) ("storeAufsDirRefObj: referencing %p %d/%d\n", e, e->swap_dirn,
	e->swap_filen);
    if (SD->repl->Referenced)
	SD->repl->Referenced(SD->repl, e, &e->repl);
}

/*
 * storeAufsDirUnrefObj
 * This routine is called whenever the last reference to an object is
 * removed, to maintain replacement information within the storage fs.
 */
void
storeAufsDirUnrefObj(SwapDir * SD, StoreEntry * e)
{
    debug(1, 3) ("storeAufsDirUnrefObj: referencing %p %d/%d\n", e, e->swap_dirn,
	e->swap_filen);
    if (SD->repl->Dereferenced)
	SD->repl->Dereferenced(SD->repl, e, &e->repl);
}

/*
 * storeAufsDirUnlinkFile
 *
 * This routine unlinks a file and pulls it out of the bitmap.
 * It used to be in storeAufsUnlink(), however an interface change
 * forced this bit of code here. Eeek.
 */
void
storeAufsDirUnlinkFile(SwapDir * SD, sfileno f)
{
    debug(79, 3) ("storeAufsDirUnlinkFile: unlinking fileno %08X\n", f);
    /* storeAufsDirMapBitReset(SD, f); */
#if USE_TRUNCATE_NOT_UNLINK
    aioTruncate(storeAufsDirFullPath(SD, f, NULL), NULL, NULL);
#else
    aioUnlink(storeAufsDirFullPath(SD, f, NULL), NULL, NULL);
#endif
}

/*
 * Add and remove the given StoreEntry from the replacement policy in
 * use.
 */

void
storeAufsDirReplAdd(SwapDir * SD, StoreEntry * e)
{
    debug(20, 4) ("storeAufsDirReplAdd: added node %p to dir %d\n", e,
	SD->index);
    SD->repl->Add(SD->repl, e, &e->repl);
}


void
storeAufsDirReplRemove(StoreEntry * e)
{
    SwapDir *SD = INDEXSD(e->swap_dirn);
    debug(20, 4) ("storeAufsDirReplRemove: remove node %p from dir %d\n", e,
	SD->index);
    SD->repl->Remove(SD->repl, e, &e->repl);
}



/* ========== LOCAL FUNCTIONS ABOVE, GLOBAL FUNCTIONS BELOW ========== */

void
storeAufsDirStats(SwapDir * SD, StoreEntry * sentry)
{
    squidaioinfo_t *aioinfo = SD->fsdata;
    int totl_kb = 0;
    int free_kb = 0;
    int totl_in = 0;
    int free_in = 0;
    int x;
    storeAppendPrintf(sentry, "First level subdirectories: %d\n", aioinfo->l1);
    storeAppendPrintf(sentry, "Second level subdirectories: %d\n", aioinfo->l2);
    storeAppendPrintf(sentry, "Maximum Size: %d KB\n", SD->max_size);
    storeAppendPrintf(sentry, "Current Size: %d KB\n", SD->cur_size);
    storeAppendPrintf(sentry, "Percent Used: %0.2f%%\n",
	100.0 * SD->cur_size / SD->max_size);
    storeAppendPrintf(sentry, "Filemap bits in use: %d of %d (%d%%)\n",
	aioinfo->map->n_files_in_map, aioinfo->map->max_n_files,
	percent(aioinfo->map->n_files_in_map, aioinfo->map->max_n_files));
    x = storeDirGetUFSStats(SD->path, &totl_kb, &free_kb, &totl_in, &free_in);
    if (0 == x) {
	storeAppendPrintf(sentry, "Filesystem Space in use: %d/%d KB (%d%%)\n",
	    totl_kb - free_kb,
	    totl_kb,
	    percent(totl_kb - free_kb, totl_kb));
	storeAppendPrintf(sentry, "Filesystem Inodes in use: %d/%d (%d%%)\n",
	    totl_in - free_in,
	    totl_in,
	    percent(totl_in - free_in, totl_in));
    }
    storeAppendPrintf(sentry, "Flags:");
    if (SD->flags.selected)
	storeAppendPrintf(sentry, " SELECTED");
    if (SD->flags.read_only)
	storeAppendPrintf(sentry, " READ-ONLY");
    storeAppendPrintf(sentry, "\n");
}

static struct cache_dir_option options[] =
{
#if NOT_YET_DONE
    {"L1", storeAufsDirParseL1, storeAufsDirDumpL1},
    {"L2", storeAufsDirParseL2, storeAufsDirDumpL2},
#endif
    {NULL, NULL}
};

/*
 * storeAufsDirReconfigure
 *
 * This routine is called when the given swapdir needs reconfiguring 
 */
static void
storeAufsDirReconfigure(SwapDir * sd, int index, char *path)
{
    int i;
    int size;
    int l1;
    int l2;

    i = GetInteger();
    size = i << 10;		/* Mbytes to kbytes */
    if (size <= 0)
	fatal("storeAufsDirReconfigure: invalid size value");
    i = GetInteger();
    l1 = i;
    if (l1 <= 0)
	fatal("storeAufsDirReconfigure: invalid level 1 directories value");
    i = GetInteger();
    l2 = i;
    if (l2 <= 0)
	fatal("storeAufsDirReconfigure: invalid level 2 directories value");

    /* just reconfigure it */
    if (size == sd->max_size)
	debug(3, 1) ("Cache dir '%s' size remains unchanged at %d KB\n",
	    path, size);
    else
	debug(3, 1) ("Cache dir '%s' size changed to %d KB\n",
	    path, size);
    sd->max_size = size;

    parse_cachedir_options(sd, options, 0);

    return;
}

void
storeAufsDirDump(StoreEntry * entry, SwapDir * s)
{
    squidaioinfo_t *aioinfo = (squidaioinfo_t *) s->fsdata;
    storeAppendPrintf(entry, " %d %d %d",
	s->max_size >> 10,
	aioinfo->l1,
	aioinfo->l2);
    dump_cachedir_options(entry, options, s);
}

/*
 * Only "free" the filesystem specific stuff here
 */
static void
storeAufsDirFree(SwapDir * s)
{
    squidaioinfo_t *aioinfo = (squidaioinfo_t *) s->fsdata;
    if (aioinfo->swaplog_fd > -1) {
	file_close(aioinfo->swaplog_fd);
	aioinfo->swaplog_fd = -1;
    }
    filemapFreeMemory(aioinfo->map);
    xfree(aioinfo);
    s->fsdata = NULL;		/* Will aid debugging... */
}

char *
storeAufsDirFullPath(SwapDir * SD, sfileno filn, char *fullpath)
{
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    squidaioinfo_t *aioinfo = (squidaioinfo_t *) SD->fsdata;
    int L1 = aioinfo->l1;
    int L2 = aioinfo->l2;
    if (!fullpath)
	fullpath = fullfilename;
    fullpath[0] = '\0';
    snprintf(fullpath, SQUID_MAXPATHLEN, "%s/%02X/%02X/%08X",
	SD->path,
	((filn / L2) / L2) % L1,
	(filn / L2) % L2,
	filn);
    return fullpath;
}

/*
 * storeAufsCleanupDoubleCheck
 *
 * This is called by storeCleanup() if -S was given on the command line.
 */
static int
storeAufsCleanupDoubleCheck(SwapDir * sd, StoreEntry * e)
{
    struct stat sb;
    if (stat(storeAufsDirFullPath(sd, e->swap_filen, NULL), &sb) < 0) {
	debug(20, 0) ("storeAufsCleanupDoubleCheck: MISSING SWAP FILE\n");
	debug(20, 0) ("storeAufsCleanupDoubleCheck: FILENO %08X\n", e->swap_filen);
	debug(20, 0) ("storeAufsCleanupDoubleCheck: PATH %s\n",
	    storeAufsDirFullPath(sd, e->swap_filen, NULL));
	storeEntryDump(e, 0);
	return -1;
    }
    if (e->swap_file_sz != sb.st_size) {
	debug(20, 0) ("storeAufsCleanupDoubleCheck: SIZE MISMATCH\n");
	debug(20, 0) ("storeAufsCleanupDoubleCheck: FILENO %08X\n", e->swap_filen);
	debug(20, 0) ("storeAufsCleanupDoubleCheck: PATH %s\n",
	    storeAufsDirFullPath(sd, e->swap_filen, NULL));
	debug(20, 0) ("storeAufsCleanupDoubleCheck: ENTRY SIZE: %ld, FILE SIZE: %ld\n",
	    (long int) e->swap_file_sz, (long int) sb.st_size);
	storeEntryDump(e, 0);
	return -1;
    }
    return 0;
}

/*
 * storeAufsDirParse *
 * Called when a *new* fs is being setup.
 */
static void
storeAufsDirParse(SwapDir * sd, int index, char *path)
{
    int i;
    int size;
    int l1;
    int l2;
    squidaioinfo_t *aioinfo;

    i = GetInteger();
    size = i << 10;		/* Mbytes to kbytes */
    if (size <= 0)
	fatal("storeAufsDirParse: invalid size value");
    i = GetInteger();
    l1 = i;
    if (l1 <= 0)
	fatal("storeAufsDirParse: invalid level 1 directories value");
    i = GetInteger();
    l2 = i;
    if (l2 <= 0)
	fatal("storeAufsDirParse: invalid level 2 directories value");

    aioinfo = xmalloc(sizeof(squidaioinfo_t));
    if (aioinfo == NULL)
	fatal("storeAufsDirParse: couldn't xmalloc() squidaioinfo_t!\n");

    sd->index = index;
    sd->path = xstrdup(path);
    sd->max_size = size;
    sd->fsdata = aioinfo;
    aioinfo->l1 = l1;
    aioinfo->l2 = l2;
    aioinfo->swaplog_fd = -1;
    aioinfo->map = NULL;	/* Debugging purposes */
    aioinfo->suggest = 0;
    sd->init = storeAufsDirInit;
    sd->newfs = storeAufsDirNewfs;
    sd->dump = storeAufsDirDump;
    sd->freefs = storeAufsDirFree;
    sd->dblcheck = storeAufsCleanupDoubleCheck;
    sd->statfs = storeAufsDirStats;
    sd->maintainfs = storeAufsDirMaintain;
    sd->checkobj = storeAufsDirCheckObj;
    sd->refobj = storeAufsDirRefObj;
    sd->unrefobj = storeAufsDirUnrefObj;
    sd->callback = aioCheckCallbacks;
    sd->sync = aioSync;
    sd->obj.create = storeAufsCreate;
    sd->obj.open = storeAufsOpen;
    sd->obj.close = storeAufsClose;
    sd->obj.read = storeAufsRead;
    sd->obj.write = storeAufsWrite;
    sd->obj.unlink = storeAufsUnlink;
    sd->log.open = storeAufsDirOpenSwapLog;
    sd->log.close = storeAufsDirCloseSwapLog;
    sd->log.write = storeAufsDirSwapLog;
    sd->log.clean.start = storeAufsDirWriteCleanStart;
    sd->log.clean.nextentry = storeAufsDirCleanLogNextEntry;
    sd->log.clean.done = storeAufsDirWriteCleanDone;

    parse_cachedir_options(sd, options, 0);

    /* Initialise replacement policy stuff */
    sd->repl = createRemovalPolicy(Config.replPolicy);
}

/*
 * Initial setup / end destruction
 */
static void
storeAufsDirDone(void)
{
    aioDone();
    memPoolDestroy(&squidaio_state_pool);
    memPoolDestroy(&aufs_qread_pool);
    memPoolDestroy(&aufs_qwrite_pool);
    asyncufs_initialised = 0;
}

void
storeFsSetup_aufs(storefs_entry_t * storefs)
{
    assert(!asyncufs_initialised);
    storefs->parsefunc = storeAufsDirParse;
    storefs->reconfigurefunc = storeAufsDirReconfigure;
    storefs->donefunc = storeAufsDirDone;
    squidaio_state_pool = memPoolCreate("AUFS IO State data", sizeof(squidaiostate_t));
    aufs_qread_pool = memPoolCreate("AUFS Queued read data",
	sizeof(queued_read));
    aufs_qwrite_pool = memPoolCreate("AUFS Queued write data",
	sizeof(queued_write));

    asyncufs_initialised = 1;
    aioInit();
}
