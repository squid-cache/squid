
/*
 * $Id: store_dir_diskd.cc,v 1.60 2002/04/01 21:53:21 hno Exp $
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

#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>

#include "store_diskd.h"

#define DefaultLevelOneDirs     16
#define DefaultLevelTwoDirs     256
#define STORE_META_BDISKDZ 4096

diskd_stats_t diskd_stats;

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

static int n_diskd_dirs = 0;
static int *diskd_dir_index = NULL;
MemPool *diskd_state_pool = NULL;
static int diskd_initialised = 0;

static char *storeDiskdDirSwapSubDir(SwapDir *, int subdirn);
static int storeDiskdDirCreateDirectory(const char *path, int);
static int storeDiskdDirVerifyCacheDirs(SwapDir *);
static int storeDiskdDirVerifyDirectory(const char *path);
static void storeDiskdDirCreateSwapSubDirs(SwapDir *);
static char *storeDiskdDirSwapLogFile(SwapDir *, const char *);
static EVH storeDiskdDirRebuildFromDirectory;
static EVH storeDiskdDirRebuildFromSwapLog;
static int storeDiskdDirGetNextFile(RebuildState *, sfileno *, int *size);
static StoreEntry *storeDiskdDirAddDiskRestore(SwapDir * SD, const cache_key * key,
    sfileno file_number,
    size_t swap_file_sz,
    time_t expires,
    time_t timestamp,
    time_t lastref,
    time_t lastmod,
    u_num32 refcount,
    u_short flags,
    int clean);
static void storeDiskdDirRebuild(SwapDir * sd);
static void storeDiskdDirCloseTmpSwapLog(SwapDir * sd);
static FILE *storeDiskdDirOpenTmpSwapLog(SwapDir *, int *, int *);
static STLOGOPEN storeDiskdDirOpenSwapLog;
static STINIT storeDiskdDirInit;
static STFREE storeDiskdDirFree;
static STLOGCLEANSTART storeDiskdDirWriteCleanStart;
static STLOGCLEANNEXTENTRY storeDiskdDirCleanLogNextEntry;
static STLOGCLEANWRITE storeDiskdDirWriteCleanEntry;
static STLOGCLEANDONE storeDiskdDirWriteCleanDone;
static STLOGCLOSE storeDiskdDirCloseSwapLog;
static STLOGWRITE storeDiskdDirSwapLog;
static STNEWFS storeDiskdDirNewfs;
static STDUMP storeDiskdDirDump;
static STMAINTAINFS storeDiskdDirMaintain;
static STCHECKOBJ storeDiskdDirCheckObj;
static STREFOBJ storeDiskdDirRefObj;
static STUNREFOBJ storeDiskdDirUnrefObj;
static QS rev_int_sort;
static int storeDiskdDirClean(int swap_index);
static EVH storeDiskdDirCleanEvent;
static int storeDiskdDirIs(SwapDir * sd);
static int storeDiskdFilenoBelongsHere(int fn, int F0, int F1, int F2);
static int storeDiskdCleanupDoubleCheck(SwapDir *, StoreEntry *);
static void storeDiskdDirStats(SwapDir *, StoreEntry *);
static void storeDiskdDirInitBitmap(SwapDir *);
static int storeDiskdDirValidFileno(SwapDir *, sfileno, int);
static void storeDiskdStats(StoreEntry * sentry);
static void storeDiskdDirSync(SwapDir *);

/* The only externally visible interface */
STSETUP storeFsSetup_diskd;

/*
 * These functions were ripped straight out of the heart of store_dir.c.
 * They assume that the given filenum is on a diskd partiton, which may or
 * may not be true.. 
 * XXX this evilness should be tidied up at a later date!
 */

static int
storeDiskdDirMapBitTest(SwapDir * SD, sfileno filn)
{
    diskdinfo_t *diskdinfo;
    diskdinfo = SD->fsdata;
    return file_map_bit_test(diskdinfo->map, filn);
}

static void
storeDiskdDirMapBitSet(SwapDir * SD, sfileno filn)
{
    diskdinfo_t *diskdinfo;
    diskdinfo = SD->fsdata;
    file_map_bit_set(diskdinfo->map, filn);
}

void
storeDiskdDirMapBitReset(SwapDir * SD, sfileno filn)
{
    diskdinfo_t *diskdinfo;
    diskdinfo = SD->fsdata;
    /* 
     * We have to test the bit before calling file_map_bit_reset.
     * file_map_bit_reset doesn't do bounds checking.  It assumes
     * filn is a valid file number, but it might not be because
     * the map is dynamic in size.  Also clearing an already clear
     * bit puts the map counter of-of-whack.
     */
    if (file_map_bit_test(diskdinfo->map, filn))
	file_map_bit_reset(diskdinfo->map, filn);
}

int
storeDiskdDirMapBitAllocate(SwapDir * SD)
{
    diskdinfo_t *diskdinfo = SD->fsdata;
    int fn;
    fn = file_map_allocate(diskdinfo->map, diskdinfo->suggest);
    file_map_bit_set(diskdinfo->map, fn);
    diskdinfo->suggest = fn + 1;
    return fn;
}

/*
 * Initialise the diskd bitmap
 *
 * If there already is a bitmap, and the numobjects is larger than currently
 * configured, we allocate a new bitmap and 'grow' the old one into it.
 */
static void
storeDiskdDirInitBitmap(SwapDir * sd)
{
    diskdinfo_t *diskdinfo = sd->fsdata;

    if (diskdinfo->map == NULL) {
	/* First time */
	diskdinfo->map = file_map_create();
    } else if (diskdinfo->map->max_n_files) {
	/* it grew, need to expand */
	/* XXX We don't need it anymore .. */
    }
    /* else it shrunk, and we leave the old one in place */
}

static char *
storeDiskdDirSwapSubDir(SwapDir * sd, int subdirn)
{
    diskdinfo_t *diskdinfo = sd->fsdata;

    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    assert(0 <= subdirn && subdirn < diskdinfo->l1);
    snprintf(fullfilename, SQUID_MAXPATHLEN, "%s/%02X", sd->path, subdirn);
    return fullfilename;
}

static int
storeDiskdDirCreateDirectory(const char *path, int should_exist)
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
storeDiskdDirVerifyDirectory(const char *path)
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
 * This function is called by storeDiskdDirInit().  If this returns < 0,
 * then Squid exits, complains about swap directories not
 * existing, and instructs the admin to run 'squid -z'
 */
static int
storeDiskdDirVerifyCacheDirs(SwapDir * sd)
{
    diskdinfo_t *diskdinfo = sd->fsdata;
    int j;
    const char *path = sd->path;

    if (storeDiskdDirVerifyDirectory(path) < 0)
	return -1;
    for (j = 0; j < diskdinfo->l1; j++) {
	path = storeDiskdDirSwapSubDir(sd, j);
	if (storeDiskdDirVerifyDirectory(path) < 0)
	    return -1;
    }
    return 0;
}

static void
storeDiskdDirCreateSwapSubDirs(SwapDir * sd)
{
    diskdinfo_t *diskdinfo = sd->fsdata;
    int i, k;
    int should_exist;
    LOCAL_ARRAY(char, name, MAXPATHLEN);
    for (i = 0; i < diskdinfo->l1; i++) {
	snprintf(name, MAXPATHLEN, "%s/%02X", sd->path, i);
	if (storeDiskdDirCreateDirectory(name, 0))
	    should_exist = 0;
	else
	    should_exist = 1;
	debug(47, 1) ("Making directories in %s\n", name);
	for (k = 0; k < diskdinfo->l2; k++) {
	    snprintf(name, MAXPATHLEN, "%s/%02X/%02X", sd->path, i, k);
	    storeDiskdDirCreateDirectory(name, should_exist);
	}
    }
}

static char *
storeDiskdDirSwapLogFile(SwapDir * sd, const char *ext)
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
storeDiskdDirOpenSwapLog(SwapDir * sd)
{
    diskdinfo_t *diskdinfo = sd->fsdata;
    char *path;
    int fd;
    path = storeDiskdDirSwapLogFile(sd, NULL);
    fd = file_open(path, O_WRONLY | O_CREAT);
    if (fd < 0) {
	debug(50, 1) ("%s: %s\n", path, xstrerror());
	fatal("storeDiskdDirOpenSwapLog: Failed to open swap log.");
    }
    debug(47, 3) ("Cache Dir #%d log opened on FD %d\n", sd->index, fd);
    diskdinfo->swaplog_fd = fd;
    if (0 == n_diskd_dirs)
	assert(NULL == diskd_dir_index);
    n_diskd_dirs++;
    assert(n_diskd_dirs <= Config.cacheSwap.n_configured);
}

static void
storeDiskdDirCloseSwapLog(SwapDir * sd)
{
    diskdinfo_t *diskdinfo = sd->fsdata;
    if (diskdinfo->swaplog_fd < 0)	/* not open */
	return;
    file_close(diskdinfo->swaplog_fd);
    debug(47, 3) ("Cache Dir #%d log closed on FD %d\n",
	sd->index, diskdinfo->swaplog_fd);
    diskdinfo->swaplog_fd = -1;
    n_diskd_dirs--;
    assert(n_diskd_dirs >= 0);
    if (0 == n_diskd_dirs)
	safe_free(diskd_dir_index);
}

static void
storeDiskdDirInit(SwapDir * sd)
{
    static int started_clean_event = 0;
    int x;
    int i;
    int rfd;
    int ikey;
    const char *args[5];
    char skey1[32];
    char skey2[32];
    char skey3[32];
    diskdinfo_t *diskdinfo = sd->fsdata;
    static const char *errmsg =
    "\tFailed to verify one of the swap directories, Check cache.log\n"
    "\tfor details.  Run 'squid -z' to create swap directories\n"
    "\tif needed, or if running Squid for the first time.";

    ikey = (getpid() << 10) + (sd->index << 2);
    ikey &= 0x7fffffff;
    diskdinfo->smsgid = msgget((key_t) ikey, 0700 | IPC_CREAT);
    if (diskdinfo->smsgid < 0) {
	debug(50, 0) ("storeDiskdInit: msgget: %s\n", xstrerror());
	fatal("msgget failed");
    }
    diskdinfo->rmsgid = msgget((key_t) (ikey + 1), 0700 | IPC_CREAT);
    if (diskdinfo->rmsgid < 0) {
	debug(50, 0) ("storeDiskdInit: msgget: %s\n", xstrerror());
	fatal("msgget failed");
    }
    diskdinfo->shm.id = shmget((key_t) (ikey + 2),
	SHMBUFS * SHMBUF_BLKSZ, 0600 | IPC_CREAT);
    if (diskdinfo->shm.id < 0) {
	debug(50, 0) ("storeDiskdInit: shmget: %s\n", xstrerror());
	fatal("shmget failed");
    }
    diskdinfo->shm.buf = shmat(diskdinfo->shm.id, NULL, 0);
    if (diskdinfo->shm.buf == (void *) -1) {
	debug(50, 0) ("storeDiskdInit: shmat: %s\n", xstrerror());
	fatal("shmat failed");
    }
    diskdinfo->shm.inuse_map = xcalloc((SHMBUFS + 7) / 8, 1);
    diskd_stats.shmbuf_count += SHMBUFS;
    for (i = 0; i < SHMBUFS; i++) {
	CBIT_SET(diskdinfo->shm.inuse_map, i);
	storeDiskdShmPut(sd, i * SHMBUF_BLKSZ);
    }
    snprintf(skey1, 32, "%d", ikey);
    snprintf(skey2, 32, "%d", ikey + 1);
    snprintf(skey3, 32, "%d", ikey + 2);
    args[0] = "diskd";
    args[1] = skey1;
    args[2] = skey2;
    args[3] = skey3;
    args[4] = NULL;
#if HAVE_POLL && defined(_SQUID_OSF_)
    /* pipes and poll() don't get along on DUNIX -DW */
    x = ipcCreate(IPC_TCP_SOCKET,
#else
    x = ipcCreate(IPC_FIFO,
#endif
	Config.Program.diskd,
	args,
	"diskd",
	&rfd,
	&diskdinfo->wfd);
    if (x < 0)
	fatalf("execl: %s", Config.Program.diskd);
    if (rfd != diskdinfo->wfd)
	comm_close(rfd);
    fd_note(diskdinfo->wfd, "squid -> diskd");
    commSetTimeout(diskdinfo->wfd, -1, NULL, NULL);
    commSetNonBlocking(diskdinfo->wfd);
    storeDiskdDirInitBitmap(sd);
    if (storeDiskdDirVerifyCacheDirs(sd) < 0)
	fatal(errmsg);
    storeDiskdDirOpenSwapLog(sd);
    storeDiskdDirRebuild(sd);
    if (!started_clean_event) {
	eventAdd("storeDirClean", storeDiskdDirCleanEvent, NULL, 15.0, 1);
	started_clean_event = 1;
    }
    (void) storeDirGetBlkSize(sd->path, &sd->fs.blksize);
}


static void
storeDiskdStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "sent_count: %d\n", diskd_stats.sent_count);
    storeAppendPrintf(sentry, "recv_count: %d\n", diskd_stats.recv_count);
    storeAppendPrintf(sentry, "max_away: %d\n", diskd_stats.max_away);
    storeAppendPrintf(sentry, "max_shmuse: %d\n", diskd_stats.max_shmuse);
    storeAppendPrintf(sentry, "open_fail_queue_len: %d\n", diskd_stats.open_fail_queue_len);
    storeAppendPrintf(sentry, "block_queue_len: %d\n", diskd_stats.block_queue_len);
    diskd_stats.max_away = diskd_stats.max_shmuse = 0;
    storeAppendPrintf(sentry, "\n             OPS SUCCESS    FAIL\n");
    storeAppendPrintf(sentry, "%7s %7d %7d %7d\n",
	"open", diskd_stats.open.ops, diskd_stats.open.success, diskd_stats.open.fail);
    storeAppendPrintf(sentry, "%7s %7d %7d %7d\n",
	"create", diskd_stats.create.ops, diskd_stats.create.success, diskd_stats.create.fail);
    storeAppendPrintf(sentry, "%7s %7d %7d %7d\n",
	"close", diskd_stats.close.ops, diskd_stats.close.success, diskd_stats.close.fail);
    storeAppendPrintf(sentry, "%7s %7d %7d %7d\n",
	"unlink", diskd_stats.unlink.ops, diskd_stats.unlink.success, diskd_stats.unlink.fail);
    storeAppendPrintf(sentry, "%7s %7d %7d %7d\n",
	"read", diskd_stats.read.ops, diskd_stats.read.success, diskd_stats.read.fail);
    storeAppendPrintf(sentry, "%7s %7d %7d %7d\n",
	"write", diskd_stats.write.ops, diskd_stats.write.success, diskd_stats.write.fail);
}

/*
 * storeDiskdDirSync
 *
 * Sync any pending data. We just sit around and read the queue
 * until the data has finished writing.
 */
static void
storeDiskdDirSync(SwapDir * SD)
{
    static time_t lastmsg = 0;
    diskdinfo_t *diskdinfo = SD->fsdata;
    while (diskdinfo->away > 0) {
	if (squid_curtime > lastmsg) {
	    debug(47, 1) ("storeDiskdDirSync: %d messages away\n",
		diskdinfo->away);
	    lastmsg = squid_curtime;
	}
	storeDiskdDirCallback(SD);
    }
}


/*
 * storeDiskdDirCallback
 *
 * Handle callbacks. If we have more than magic2 requests away, we block
 * until the queue is below magic2. Otherwise, we simply return when we
 * don't get a message.
 */
int
storeDiskdDirCallback(SwapDir * SD)
{
    diomsg M;
    int x;
    diskdinfo_t *diskdinfo = SD->fsdata;
    int retval = 0;

    if (diskdinfo->away >= diskdinfo->magic2) {
	diskd_stats.block_queue_len++;
	retval = 1;		/* We might not have anything to do, but our queue
				 * is full.. */
    }
    if (diskd_stats.sent_count - diskd_stats.recv_count >
	diskd_stats.max_away) {
	diskd_stats.max_away = diskd_stats.sent_count - diskd_stats.recv_count;
    }
    while (1) {
	memset(&M, '\0', sizeof(M));
	x = msgrcv(diskdinfo->rmsgid, &M, msg_snd_rcv_sz, 0, IPC_NOWAIT);
	if (x < 0)
	    break;
	else if (x != msg_snd_rcv_sz) {
	    debug(81, 1) ("storeDiskdDirCallback: msgget returns %d\n",
		x);
	    break;
	}
	diskd_stats.recv_count++;
	diskdinfo->away--;
	storeDiskdHandle(&M);
	retval = 1;		/* Return that we've actually done some work */
	if (M.shm_offset > -1)
	    storeDiskdShmPut(SD, (off_t) M.shm_offset);
    }
    return retval;
}



static void
storeDiskdDirRebuildFromDirectory(void *data)
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
    debug(20, 3) ("storeDiskdDirRebuildFromDirectory: DIR #%d\n", rb->sd->index);
    for (count = 0; count < rb->speed; count++) {
	assert(fd == -1);
	fd = storeDiskdDirGetNextFile(rb, &filn, &size);
	if (fd == -2) {
	    debug(20, 1) ("Done scanning %s swaplog (%d entries)\n",
		rb->sd->path, rb->n_read);
	    store_dirs_rebuilding--;
	    storeDiskdDirCloseTmpSwapLog(rb->sd);
	    storeRebuildComplete(&rb->counts);
	    cbdataFree(rb);
	    return;
	} else if (fd < 0) {
	    continue;
	}
	assert(fd > -1);
	/* lets get file stats here */
	if (fstat(fd, &sb) < 0) {
	    debug(20, 1) ("storeDiskdDirRebuildFromDirectory: fstat(FD %d): %s\n",
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
	    debug(20, 1) ("storeDiskdDirRebuildFromDirectory: read(FD %d): %s\n",
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
	    debug(20, 1) ("storeDiskdDirRebuildFromDirectory: failed to get meta data\n");
	    /* XXX shouldn't this be a call to storeDiskdUnlink ? */
	    storeDiskdDirUnlinkFile(SD, filn);
	    continue;
	}
	debug(20, 3) ("storeDiskdDirRebuildFromDirectory: successful swap meta unpacking\n");
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
	    debug(20, 1) ("storeDiskdDirRebuildFromDirectory: NULL key\n");
	    storeDiskdDirUnlinkFile(SD, filn);
	    continue;
	}
	tmpe.hash.key = key;
	/* check sizes */
	if (tmpe.swap_file_sz == 0) {
	    tmpe.swap_file_sz = sb.st_size;
	} else if (tmpe.swap_file_sz == sb.st_size - swap_hdr_len) {
	    tmpe.swap_file_sz = sb.st_size;
	} else if (tmpe.swap_file_sz != sb.st_size) {
	    debug(20, 1) ("storeDiskdDirRebuildFromDirectory: SIZE MISMATCH %ld!=%ld\n",
		(long int) tmpe.swap_file_sz, (long int) sb.st_size);
	    storeDiskdDirUnlinkFile(SD, filn);
	    continue;
	}
	if (EBIT_TEST(tmpe.flags, KEY_PRIVATE)) {
	    storeDiskdDirUnlinkFile(SD, filn);
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
	e = storeDiskdDirAddDiskRestore(SD, key,
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
    eventAdd("storeRebuild", storeDiskdDirRebuildFromDirectory, rb, 0.0, 1);
}

static void
storeDiskdDirRebuildFromSwapLog(void *data)
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
	    storeDiskdDirCloseTmpSwapLog(rb->sd);
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
	debug(20, 3) ("storeDiskdDirRebuildFromSwapLog: %s %s %08X\n",
	    swap_log_op_str[(int) s.op],
	    storeKeyText(s.key),
	    s.swap_filen);
	if (s.op == SWAP_LOG_ADD) {
	    /*
	     * Here we have some special checks for large files.
	     * I've been seeing a system crash followed by a reboot
	     * that seems to corrupt the swap log.  Squid believes
	     * that the disk holds some really large files.  It
	     * complains about using being over the high water mark
	     * and proceeds to delete files as fast as it can.  To
	     * prevent that, we call stat() on sufficiently large
	     * files (>128KB) and reject those that are missing or
	     * have the wrong size.
	     */
	    struct stat sb;
	    char *p = storeDiskdDirFullPath(SD, s.swap_filen, NULL);
	    if (s.swap_file_sz < (1 << 17)) {
		(void) 0;
	    } else if (stat(p, &sb) < 0) {
		debug(47, 2) ("its missing!: %s\n", p);
		continue;
	    } else if (sb.st_size != s.swap_file_sz) {
		debug(47, 2) ("size mismatch!: stat=%d, log=%d\n",
		    (int) sb.st_size, (int) s.swap_file_sz);
		continue;
	    } else {
		debug(47, 2) ("big file (%d bytes) checks out\n",
		    (int) s.swap_file_sz);
	    }
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
		    storeDiskdDirReplRemove(e);
		    storeDiskdDirMapBitReset(SD, e->swap_filen);
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
	if (!storeDiskdDirValidFileno(SD, s.swap_filen, 0)) {
	    rb->counts.invalid++;
	    continue;
	}
	if (EBIT_TEST(s.flags, KEY_PRIVATE)) {
	    rb->counts.badflags++;
	    continue;
	}
	e = storeGet(s.key);
	used = storeDiskdDirMapBitTest(SD, s.swap_filen);
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
		storeDiskdDirUnrefObj(SD, e);
	    } else {
		debug_trap("storeDiskdDirRebuildFromSwapLog: bad condition");
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
		storeDiskdDirReplRemove(e);
		/* Make sure we don't actually unlink the file */
		storeDiskdDirMapBitReset(SD, e->swap_filen);
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
	e = storeDiskdDirAddDiskRestore(SD, s.key,
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
    eventAdd("storeRebuild", storeDiskdDirRebuildFromSwapLog, rb, 0.0, 1);
}

static int
storeDiskdDirGetNextFile(RebuildState * rb, sfileno * filn_p, int *size)
{
    SwapDir *SD = rb->sd;
    diskdinfo_t *diskdinfo = SD->fsdata;
    int fd = -1;
    int used = 0;
    int dirs_opened = 0;
    debug(20, 3) ("storeDiskdDirGetNextFile: flag=%d, %d: /%02X/%02X\n",
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
		debug(50, 1) ("storeDiskdDirGetNextFile: opendir: %s: %s\n",
		    rb->fullpath, xstrerror());
	    } else {
		rb->entry = readdir(rb->td);	/* skip . and .. */
		rb->entry = readdir(rb->td);
		if (rb->entry == NULL && errno == ENOENT)
		    debug(20, 1) ("storeDiskdDirGetNextFile: directory does not exist!.\n");
		debug(20, 3) ("storeDiskdDirGetNextFile: Directory %s\n", rb->fullpath);
	    }
	}
	if (rb->td != NULL && (rb->entry = readdir(rb->td)) != NULL) {
	    rb->in_dir++;
	    if (sscanf(rb->entry->d_name, "%x", &rb->fn) != 1) {
		debug(20, 3) ("storeDiskdDirGetNextFile: invalid %s\n",
		    rb->entry->d_name);
		continue;
	    }
	    if (!storeDiskdFilenoBelongsHere(rb->fn, rb->sd->index, rb->curlvl1, rb->curlvl2)) {
		debug(20, 3) ("storeDiskdDirGetNextFile: %08X does not belong in %d/%d/%d\n",
		    rb->fn, rb->sd->index, rb->curlvl1, rb->curlvl2);
		continue;
	    }
	    used = storeDiskdDirMapBitTest(SD, rb->fn);
	    if (used) {
		debug(20, 3) ("storeDiskdDirGetNextFile: Locked, continuing with next.\n");
		continue;
	    }
	    snprintf(rb->fullfilename, SQUID_MAXPATHLEN, "%s/%s",
		rb->fullpath, rb->entry->d_name);
	    debug(20, 3) ("storeDiskdDirGetNextFile: Opening %s\n", rb->fullfilename);
	    fd = file_open(rb->fullfilename, O_RDONLY);
	    if (fd < 0)
		debug(50, 1) ("storeDiskdDirGetNextFile: %s: %s\n", rb->fullfilename, xstrerror());
	    else
		store_open_disk_fd++;
	    continue;
	}
	if (rb->td != NULL)
	    closedir(rb->td);
	rb->td = NULL;
	rb->in_dir = 0;
	if (++rb->curlvl2 < diskdinfo->l2)
	    continue;
	rb->curlvl2 = 0;
	if (++rb->curlvl1 < diskdinfo->l1)
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
storeDiskdDirAddDiskRestore(SwapDir * SD, const cache_key * key,
    int file_number,
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
    debug(20, 5) ("storeDiskdAddDiskRestore: %s, fileno=%08X\n", storeKeyText(key), file_number);
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
    storeDiskdDirMapBitSet(SD, e->swap_filen);
    storeHashInsert(e, key);	/* do it after we clear KEY_PRIVATE */
    storeDiskdDirReplAdd(SD, e);
    return e;
}

CBDATA_TYPE(RebuildState);

static void
storeDiskdDirRebuild(SwapDir * sd)
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
     * we'll use storeDiskdDirRebuildFromSwapLog(), otherwise we'll
     * use storeDiskdDirRebuildFromDirectory() to open up each file
     * and suck in the meta data.
     */
    fp = storeDiskdDirOpenTmpSwapLog(sd, &clean, &zero);
    if (fp == NULL || zero) {
	if (fp != NULL)
	    fclose(fp);
	func = storeDiskdDirRebuildFromDirectory;
    } else {
	func = storeDiskdDirRebuildFromSwapLog;
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
storeDiskdDirCloseTmpSwapLog(SwapDir * sd)
{
    diskdinfo_t *diskdinfo = sd->fsdata;
    char *swaplog_path = xstrdup(storeDiskdDirSwapLogFile(sd, NULL));
    char *new_path = xstrdup(storeDiskdDirSwapLogFile(sd, ".new"));
    int fd;
    file_close(diskdinfo->swaplog_fd);
#ifdef _SQUID_OS2_
    if (unlink(swaplog_path) < 0) {
	debug(50, 0) ("%s: %s\n", swaplog_path, xstrerror());
	fatal("storeDiskdDirCloseTmpSwapLog: unlink failed");
    }
#endif
    if (xrename(new_path, swaplog_path) < 0) {
	fatal("storeDiskdDirCloseTmpSwapLog: rename failed");
    }
    fd = file_open(swaplog_path, O_WRONLY | O_CREAT);
    if (fd < 0) {
	debug(50, 1) ("%s: %s\n", swaplog_path, xstrerror());
	fatal("storeDiskdDirCloseTmpSwapLog: Failed to open swap log.");
    }
    safe_free(swaplog_path);
    safe_free(new_path);
    diskdinfo->swaplog_fd = fd;
    debug(47, 3) ("Cache Dir #%d log opened on FD %d\n", sd->index, fd);
}

static FILE *
storeDiskdDirOpenTmpSwapLog(SwapDir * sd, int *clean_flag, int *zero_flag)
{
    diskdinfo_t *diskdinfo = sd->fsdata;
    char *swaplog_path = xstrdup(storeDiskdDirSwapLogFile(sd, NULL));
    char *clean_path = xstrdup(storeDiskdDirSwapLogFile(sd, ".last-clean"));
    char *new_path = xstrdup(storeDiskdDirSwapLogFile(sd, ".new"));
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
    if (diskdinfo->swaplog_fd >= 0)
	file_close(diskdinfo->swaplog_fd);
    /* open a write-only FD for the new log */
    fd = file_open(new_path, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) {
	debug(50, 1) ("%s: %s\n", new_path, xstrerror());
	fatal("storeDirOpenTmpSwapLog: Failed to open swap log.");
    }
    diskdinfo->swaplog_fd = fd;
    /* open a read-only stream of the old log */
    fp = fopen(swaplog_path, "r");
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
 * Begin the process to write clean cache state.  For DISKD this means
 * opening some log files and allocating write buffers.  Return 0 if
 * we succeed, and assign the 'func' and 'data' return pointers.
 */
static int
storeDiskdDirWriteCleanStart(SwapDir * sd)
{
    struct _clean_state *state = xcalloc(1, sizeof(*state));
    struct stat sb;
    sd->log.clean.write = NULL;
    sd->log.clean.state = NULL;
    state->new = xstrdup(storeDiskdDirSwapLogFile(sd, ".clean"));
    state->cur = xstrdup(storeDiskdDirSwapLogFile(sd, NULL));
    state->cln = xstrdup(storeDiskdDirSwapLogFile(sd, ".last-clean"));
    state->outbuf = xcalloc(CLEAN_BUF_SZ, 1);
    state->outbuf_offset = 0;
    state->walker = sd->repl->WalkInit(sd->repl);
    unlink(state->cln);
    state->fd = file_open(state->new, O_WRONLY | O_CREAT | O_TRUNC);
    if (state->fd < 0) {
	xfree(state->new);
	xfree(state->cur);
	xfree(state->cln);
	xfree(state);
	return -1;
    }
    debug(20, 3) ("storeDirWriteCleanLogs: opened %s, FD %d\n",
	state->new, state->fd);
#if HAVE_FCHMOD
    if (stat(state->cur, &sb) == 0)
	fchmod(state->fd, sb.st_mode);
#endif
    sd->log.clean.write = storeDiskdDirWriteCleanEntry;
    sd->log.clean.state = state;
    return 0;
}

/*
 * Get the next entry that is a candidate for clean log writing
 */
const StoreEntry *
storeDiskdDirCleanLogNextEntry(SwapDir * sd)
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
storeDiskdDirWriteCleanEntry(SwapDir * sd, const StoreEntry * e)
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
storeDiskdDirWriteCleanDone(SwapDir * sd)
{
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
    storeDiskdDirCloseSwapLog(sd);
    /* rename */
    if (state->fd >= 0) {
#ifdef _SQUID_OS2_
	file_close(state->fd);
	state->fd = -1;
	if (unlink(cur) < 0)
	    debug(50, 0) ("storeDirWriteCleanLogs: unlinkd failed: %s, %s\n",
		xstrerror(), cur);
#endif
	xrename(state->new, state->cur);
    }
    /* touch a timestamp file if we're not still validating */
    if (store_dirs_rebuilding)
	(void) 0;
    else if (state->fd < 0)
	(void) 0;
    else
	file_close(file_open(state->cln, O_WRONLY | O_CREAT | O_TRUNC));
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
storeDiskdDirSwapLog(const SwapDir * sd, const StoreEntry * e, int op)
{
    diskdinfo_t *diskdinfo = sd->fsdata;
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
    file_write(diskdinfo->swaplog_fd,
	-1,
	s,
	sizeof(storeSwapLogData),
	NULL,
	NULL,
	(FREE *) storeSwapLogDataFree);
}

static void
storeDiskdDirNewfs(SwapDir * sd)
{
    debug(47, 3) ("Creating swap space in %s\n", sd->path);
    storeDiskdDirCreateDirectory(sd->path, 0);
    storeDiskdDirCreateSwapSubDirs(sd);
}

static int
rev_int_sort(const void *A, const void *B)
{
    const int *i1 = A;
    const int *i2 = B;
    return *i2 - *i1;
}

static int
storeDiskdDirClean(int swap_index)
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
    diskdinfo_t *diskdinfo;
    N0 = n_diskd_dirs;
    D0 = diskd_dir_index[swap_index % N0];
    SD = &Config.cacheSwap.swapDirs[D0];
    diskdinfo = SD->fsdata;
    N1 = diskdinfo->l1;
    D1 = (swap_index / N0) % N1;
    N2 = diskdinfo->l2;
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
	if (storeDiskdDirValidFileno(SD, fn, 1))
	    if (storeDiskdDirMapBitTest(SD, fn))
		if (storeDiskdFilenoBelongsHere(fn, D0, D1, D2))
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
storeDiskdDirCleanEvent(void *unused)
{
    static int swap_index = 0;
    int i;
    int j = 0;
    int n = 0;
    /*
     * Assert that there are DISKD cache_dirs configured, otherwise
     * we should never be called.
     */
    assert(n_diskd_dirs);
    if (NULL == diskd_dir_index) {
	SwapDir *sd;
	diskdinfo_t *diskdinfo;
	/*
	 * Initialize the little array that translates DISKD cache_dir
	 * number into the Config.cacheSwap.swapDirs array index.
	 */
	diskd_dir_index = xcalloc(n_diskd_dirs, sizeof(*diskd_dir_index));
	for (i = 0, n = 0; i < Config.cacheSwap.n_configured; i++) {
	    sd = &Config.cacheSwap.swapDirs[i];
	    if (!storeDiskdDirIs(sd))
		continue;
	    diskd_dir_index[n++] = i;
	    diskdinfo = sd->fsdata;
	    j += (diskdinfo->l1 * diskdinfo->l2);
	}
	assert(n == n_diskd_dirs);
	/*
	 * Start the storeDiskdDirClean() swap_index with a random
	 * value.  j equals the total number of DISKD level 2
	 * swap directories
	 */
	swap_index = (int) (squid_random() % j);
    }
    if (0 == store_dirs_rebuilding) {
	n = storeDiskdDirClean(swap_index);
	swap_index++;
    }
    eventAdd("storeDirClean", storeDiskdDirCleanEvent, NULL,
	15.0 * exp(-0.25 * n), 1);
}

static int
storeDiskdDirIs(SwapDir * sd)
{
    if (strncmp(sd->type, "diskd", 3) == 0)
	return 1;
    return 0;
}

/*
 * Does swapfile number 'fn' belong in cachedir #F0,
 * level1 dir #F1, level2 dir #F2?
 */
static int
storeDiskdFilenoBelongsHere(int fn, int F0, int F1, int F2)
{
    int D1, D2;
    int L1, L2;
    int filn = fn;
    diskdinfo_t *diskdinfo;
    assert(F0 < Config.cacheSwap.n_configured);
    diskdinfo = Config.cacheSwap.swapDirs[F0].fsdata;
    L1 = diskdinfo->l1;
    L2 = diskdinfo->l2;
    D1 = ((filn / L2) / L2) % L1;
    if (F1 != D1)
	return 0;
    D2 = (filn / L2) % L2;
    if (F2 != D2)
	return 0;
    return 1;
}

int
storeDiskdDirValidFileno(SwapDir * SD, sfileno filn, int flag)
{
    diskdinfo_t *diskdinfo = SD->fsdata;
    if (filn < 0)
	return 0;
    /*
     * If flag is set it means out-of-range file number should
     * be considered invalid.
     */
    if (flag)
	if (filn > diskdinfo->map->max_n_files)
	    return 0;
    return 1;
}

void
storeDiskdDirMaintain(SwapDir * SD)
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
    debug(20, 3) ("storeMaintainSwapSpace: f=%f, max_scan=%d, max_remove=%d\n", f, max_scan, max_remove);
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
    debug(20, (removed ? 2 : 3)) ("storeDiskdDirMaintain: %s removed %d/%d f=%.03f max_scan=%d\n",
	SD->path, removed, max_remove, f, max_scan);
}

/*
 * storeDiskdDirCheckObj
 *
 * This routine is called by storeDirSelectSwapDir to see if the given
 * object is able to be stored on this filesystem. DISKD filesystems will
 * happily store anything as long as the LRU time isn't too small.
 */
int
storeDiskdDirCheckObj(SwapDir * SD, const StoreEntry * e)
{
    diskdinfo_t *diskdinfo = SD->fsdata;
    /* Check the queue length */
    if (diskdinfo->away >= diskdinfo->magic1)
	return -1;
    /* Calculate the storedir load relative to magic2 on a scale of 0 .. 1000 */
    /* the parse function guarantees magic2 is positivie */
    return diskdinfo->away * 1000 / diskdinfo->magic2;
}

/*
 * storeDiskdDirRefObj
 *
 * This routine is called whenever an object is referenced, so we can
 * maintain replacement information within the storage fs.
 */
void
storeDiskdDirRefObj(SwapDir * SD, StoreEntry * e)
{
    debug(1, 3) ("storeDiskdDirRefObj: referencing %p %d/%d\n", e, e->swap_dirn,
	e->swap_filen);
    if (SD->repl->Referenced)
	SD->repl->Referenced(SD->repl, e, &e->repl);
}

/*
 * storeDiskdDirUnrefObj
 * This routine is called whenever the last reference to an object is
 * removed, to maintain replacement information within the storage fs.
 */
void
storeDiskdDirUnrefObj(SwapDir * SD, StoreEntry * e)
{
    debug(1, 3) ("storeDiskdDirUnrefObj: referencing %p %d/%d\n", e,
	e->swap_dirn, e->swap_filen);
    if (SD->repl->Dereferenced)
	SD->repl->Dereferenced(SD->repl, e, &e->repl);
}

/*
 * storeDiskdDirUnlinkFile
 *
 * This is a *synchronous* unlink which is currently used in the rebuild
 * process. This is bad, but it'll have to stay until the dir rebuild
 * uses storeDiskdUnlink() ..
 */
void
storeDiskdDirUnlinkFile(SwapDir * SD, sfileno f)
{
    debug(79, 3) ("storeDiskdDirUnlinkFile: unlinking fileno %08X\n", f);
    /* storeDiskdDirMapBitReset(SD, f); */
#if USE_UNLINKD
    unlinkdUnlink(storeDiskdDirFullPath(SD, f, NULL));
#elif USE_TRUNCATE
    truncate(storeDiskdDirFullPath(SD, f, NULL), 0);
#else
    unlink(storeDiskdDirFullPath(SD, f, NULL));
#endif
}

/*
 * Add and remove the given StoreEntry from the replacement policy in
 * use.
 */

void
storeDiskdDirReplAdd(SwapDir * SD, StoreEntry * e)
{
    debug(20, 4) ("storeDiskdDirReplAdd: added node %p to dir %d\n", e,
	SD->index);
    SD->repl->Add(SD->repl, e, &e->repl);
}


void
storeDiskdDirReplRemove(StoreEntry * e)
{
    SwapDir *SD;
    if (e->swap_dirn < 0)
	return;
    SD = INDEXSD(e->swap_dirn);
    debug(20, 4) ("storeDiskdDirReplRemove: remove node %p from dir %d\n", e,
	SD->index);
    SD->repl->Remove(SD->repl, e, &e->repl);
}



/*
 * SHM manipulation routines
 */

void *
storeDiskdShmGet(SwapDir * sd, off_t * shm_offset)
{
    char *buf = NULL;
    diskdinfo_t *diskdinfo = sd->fsdata;
    int i;
    for (i = 0; i < SHMBUFS; i++) {
	if (CBIT_TEST(diskdinfo->shm.inuse_map, i))
	    continue;
	CBIT_SET(diskdinfo->shm.inuse_map, i);
	*shm_offset = i * SHMBUF_BLKSZ;
	buf = diskdinfo->shm.buf + (*shm_offset);
	break;
    }
    assert(buf);
    assert(buf >= diskdinfo->shm.buf);
    assert(buf < diskdinfo->shm.buf + (SHMBUFS * SHMBUF_BLKSZ));
    diskd_stats.shmbuf_count++;
    if (diskd_stats.max_shmuse < diskd_stats.shmbuf_count)
	diskd_stats.max_shmuse = diskd_stats.shmbuf_count;
    return buf;
}

void
storeDiskdShmPut(SwapDir * sd, off_t offset)
{
    int i;
    diskdinfo_t *diskdinfo = sd->fsdata;
    assert(offset >= 0);
    assert(offset < SHMBUFS * SHMBUF_BLKSZ);
    i = offset / SHMBUF_BLKSZ;
    assert(i < SHMBUFS);
    assert(CBIT_TEST(diskdinfo->shm.inuse_map, i));
    CBIT_CLR(diskdinfo->shm.inuse_map, i);
    diskd_stats.shmbuf_count--;
}




/* ========== LOCAL FUNCTIONS ABOVE, GLOBAL FUNCTIONS BELOW ========== */

void
storeDiskdDirStats(SwapDir * SD, StoreEntry * sentry)
{
    diskdinfo_t *diskdinfo = SD->fsdata;
    int totl_kb = 0;
    int free_kb = 0;
    int totl_in = 0;
    int free_in = 0;
    int x;
    storeAppendPrintf(sentry, "First level subdirectories: %d\n", diskdinfo->l1);
    storeAppendPrintf(sentry, "Second level subdirectories: %d\n", diskdinfo->l2);
    storeAppendPrintf(sentry, "Maximum Size: %d KB\n", SD->max_size);
    storeAppendPrintf(sentry, "Current Size: %d KB\n", SD->cur_size);
    storeAppendPrintf(sentry, "Percent Used: %0.2f%%\n",
	100.0 * SD->cur_size / SD->max_size);
    storeAppendPrintf(sentry, "Filemap bits in use: %d of %d (%d%%)\n",
	diskdinfo->map->n_files_in_map, diskdinfo->map->max_n_files,
	percent(diskdinfo->map->n_files_in_map, diskdinfo->map->max_n_files));
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
    storeAppendPrintf(sentry, "Pending operations: %d\n", diskdinfo->away);
}

static void
storeDiskdDirParseQ1(SwapDir * sd, const char *name, const char *value, int reconfiguring)
{
    diskdinfo_t *diskdinfo = sd->fsdata;
    int old_magic1 = diskdinfo->magic1;
    diskdinfo->magic1 = atoi(value);
    if (reconfiguring && old_magic1 != diskdinfo->magic1)
	debug(3, 1) ("cache_dir '%s' new Q1 value '%d'\n",
	    sd->path, diskdinfo->magic1);
}

static void
storeDiskdDirDumpQ1(StoreEntry * e, const char *option, SwapDir * sd)
{
    diskdinfo_t *diskdinfo = sd->fsdata;
    storeAppendPrintf(e, " Q1=%d", diskdinfo->magic1);
}

static void
storeDiskdDirParseQ2(SwapDir * sd, const char *name, const char *value, int reconfiguring)
{
    diskdinfo_t *diskdinfo = sd->fsdata;
    int old_magic2 = diskdinfo->magic2;
    diskdinfo->magic2 = atoi(value);
    if (reconfiguring && old_magic2 != diskdinfo->magic2)
	debug(3, 1) ("cache_dir '%s' new Q2 value '%d'\n",
	    sd->path, diskdinfo->magic2);
}

static void
storeDiskdDirDumpQ2(StoreEntry * e, const char *option, SwapDir * sd)
{
    diskdinfo_t *diskdinfo = sd->fsdata;
    storeAppendPrintf(e, " Q2=%d", diskdinfo->magic2);
}

struct cache_dir_option options[] =
{
#if NOT_YET
    {"L1", storeDiskdDirParseL1, storeDiskdDirDumpL1},
    {"L2", storeDiskdDirParseL2, storeDiskdDirDumpL2},
#endif
    {"Q1", storeDiskdDirParseQ1, storeDiskdDirDumpQ1},
    {"Q2", storeDiskdDirParseQ2, storeDiskdDirDumpQ2},
    {NULL, NULL}
};

/*
 * storeDiskdDirReconfigure
 *
 * This routine is called when the given swapdir needs reconfiguring 
 */
static void
storeDiskdDirReconfigure(SwapDir * sd, int index, char *path)
{
    int i;
    int size;
    int l1;
    int l2;

    i = GetInteger();
    size = i << 10;		/* Mbytes to kbytes */
    if (size <= 0)
	fatal("storeDiskdDirReconfigure: invalid size value");
    i = GetInteger();
    l1 = i;
    if (l1 <= 0)
	fatal("storeDiskdDirReconfigure: invalid level 1 directories value");
    i = GetInteger();
    l2 = i;
    if (l2 <= 0)
	fatal("storeDiskdDirReconfigure: invalid level 2 directories value");

    /* just reconfigure it */
    if (size == sd->max_size)
	debug(3, 1) ("Cache dir '%s' size remains unchanged at %d KB\n",
	    path, size);
    else
	debug(3, 1) ("Cache dir '%s' size changed to %d KB\n",
	    path, size);
    sd->max_size = size;
    parse_cachedir_options(sd, options, 1);
}

void
storeDiskdDirDump(StoreEntry * entry, SwapDir * s)
{
    diskdinfo_t *diskdinfo = s->fsdata;
    storeAppendPrintf(entry, " %d %d %d",
	s->max_size >> 10,
	diskdinfo->l1,
	diskdinfo->l2);
    dump_cachedir_options(entry, options, s);
}

/*
 * Only "free" the filesystem specific stuff here
 */
static void
storeDiskdDirFree(SwapDir * s)
{
    diskdinfo_t *diskdinfo = s->fsdata;
    if (diskdinfo->swaplog_fd > -1) {
	file_close(diskdinfo->swaplog_fd);
	diskdinfo->swaplog_fd = -1;
    }
    filemapFreeMemory(diskdinfo->map);
    xfree(diskdinfo);
    s->fsdata = NULL;		/* Will aid debugging... */

}

char *
storeDiskdDirFullPath(SwapDir * SD, sfileno filn, char *fullpath)
{
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    diskdinfo_t *diskdinfo = SD->fsdata;
    int L1 = diskdinfo->l1;
    int L2 = diskdinfo->l2;
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
 * storeDiskdCleanupDoubleCheck
 *
 * This is called by storeCleanup() if -S was given on the command line.
 */
static int
storeDiskdCleanupDoubleCheck(SwapDir * sd, StoreEntry * e)
{
    struct stat sb;
    if (stat(storeDiskdDirFullPath(sd, e->swap_filen, NULL), &sb) < 0) {
	debug(20, 0) ("storeDiskdCleanupDoubleCheck: MISSING SWAP FILE\n");
	debug(20, 0) ("storeDiskdCleanupDoubleCheck: FILENO %08X\n", e->swap_filen);
	debug(20, 0) ("storeDiskdCleanupDoubleCheck: PATH %s\n",
	    storeDiskdDirFullPath(sd, e->swap_filen, NULL));
	storeEntryDump(e, 0);
	return -1;
    }
    if (e->swap_file_sz != sb.st_size) {
	debug(20, 0) ("storeDiskdCleanupDoubleCheck: SIZE MISMATCH\n");
	debug(20, 0) ("storeDiskdCleanupDoubleCheck: FILENO %08X\n", e->swap_filen);
	debug(20, 0) ("storeDiskdCleanupDoubleCheck: PATH %s\n",
	    storeDiskdDirFullPath(sd, e->swap_filen, NULL));
	debug(20, 0) ("storeDiskdCleanupDoubleCheck: ENTRY SIZE: %ld, FILE SIZE: %ld\n",
	    (long int) e->swap_file_sz, (long int) sb.st_size);
	storeEntryDump(e, 0);
	return -1;
    }
    return 0;
}

/*
 * storeDiskdDirParse
 *
 * Called when a *new* fs is being setup.
 */
static void
storeDiskdDirParse(SwapDir * sd, int index, char *path)
{
    int i;
    int size;
    int l1;
    int l2;
    diskdinfo_t *diskdinfo;

    i = GetInteger();
    size = i << 10;		/* Mbytes to kbytes */
    if (size <= 0)
	fatal("storeDiskdDirParse: invalid size value");
    i = GetInteger();
    l1 = i;
    if (l1 <= 0)
	fatal("storeDiskdDirParse: invalid level 1 directories value");
    i = GetInteger();
    l2 = i;
    if (l2 <= 0)
	fatal("storeDiskdDirParse: invalid level 2 directories value");

    sd->fsdata = diskdinfo = xcalloc(1, sizeof(*diskdinfo));
    sd->index = index;
    sd->path = xstrdup(path);
    sd->max_size = size;
    diskdinfo->l1 = l1;
    diskdinfo->l2 = l2;
    diskdinfo->swaplog_fd = -1;
    diskdinfo->map = NULL;	/* Debugging purposes */
    diskdinfo->suggest = 0;
    diskdinfo->magic1 = 64;
    diskdinfo->magic2 = 72;
    sd->init = storeDiskdDirInit;
    sd->newfs = storeDiskdDirNewfs;
    sd->dump = storeDiskdDirDump;
    sd->freefs = storeDiskdDirFree;
    sd->dblcheck = storeDiskdCleanupDoubleCheck;
    sd->statfs = storeDiskdDirStats;
    sd->maintainfs = storeDiskdDirMaintain;
    sd->checkobj = storeDiskdDirCheckObj;
    sd->refobj = storeDiskdDirRefObj;
    sd->unrefobj = storeDiskdDirUnrefObj;
    sd->callback = storeDiskdDirCallback;
    sd->sync = storeDiskdDirSync;
    sd->obj.create = storeDiskdCreate;
    sd->obj.open = storeDiskdOpen;
    sd->obj.close = storeDiskdClose;
    sd->obj.read = storeDiskdRead;
    sd->obj.write = storeDiskdWrite;
    sd->obj.unlink = storeDiskdUnlink;
    sd->log.open = storeDiskdDirOpenSwapLog;
    sd->log.close = storeDiskdDirCloseSwapLog;
    sd->log.write = storeDiskdDirSwapLog;
    sd->log.clean.start = storeDiskdDirWriteCleanStart;
    sd->log.clean.nextentry = storeDiskdDirCleanLogNextEntry;
    sd->log.clean.done = storeDiskdDirWriteCleanDone;

    parse_cachedir_options(sd, options, 0);

    /* Initialise replacement policy stuff */
    sd->repl = createRemovalPolicy(Config.replPolicy);
}

/*
 * Initial setup / end destruction
 */
static void
storeDiskdDirDone(void)
{
    memPoolDestroy(diskd_state_pool);
    diskd_initialised = 0;
}

void
storeFsSetup_diskd(storefs_entry_t * storefs)
{
    assert(!diskd_initialised);
    storefs->parsefunc = storeDiskdDirParse;
    storefs->reconfigurefunc = storeDiskdDirReconfigure;
    storefs->donefunc = storeDiskdDirDone;
    diskd_state_pool = memPoolCreate("DISKD IO State data", sizeof(diskdstate_t));
    memset(&diskd_stats, '\0', sizeof(diskd_stats));
    cachemgrRegister("diskd", "DISKD Stats", storeDiskdStats, 0, 1);
    debug(81, 1) ("diskd started\n");
    diskd_initialised = 1;
}
