
/*
 * $Id: store_dir_diskd.cc,v 1.71 2002/10/12 09:45:57 robertc Exp $
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

#include "ufscommon.h"

diskd_stats_t diskd_stats;

MemPool *diskd_state_pool = NULL;
static int diskd_initialised = 0;

static STINIT storeDiskdDirInit;
static STDUMP storeDiskdDirDump;
static STCHECKOBJ storeDiskdDirCheckObj;
static void storeDiskdDirStats(SwapDir *, StoreEntry *);
static void storeDiskdStats(StoreEntry * sentry);
static void storeDiskdDirSync(SwapDir *);
static void storeDiskdDirIOUnlinkFile(char *path);

/* The only externally visible interface */
STSETUP storeFsSetup_diskd;

static void
storeDiskdDirInit(SwapDir * sd)
{
    int x;
    int i;
    int rfd;
    int ikey;
    const char *args[5];
    char skey1[32];
    char skey2[32];
    char skey3[32];
    diskdinfo_t *diskdinfo = sd->fsdata;

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
    diskdinfo->shm.nbufs = diskdinfo->magic2 * 1.3;
    diskdinfo->shm.id = shmget((key_t) (ikey + 2),
	diskdinfo->shm.nbufs * SHMBUF_BLKSZ, 0600 | IPC_CREAT);
    if (diskdinfo->shm.id < 0) {
	debug(50, 0) ("storeDiskdInit: shmget: %s\n", xstrerror());
	fatal("shmget failed");
    }
    diskdinfo->shm.buf = shmat(diskdinfo->shm.id, NULL, 0);
    if (diskdinfo->shm.buf == (void *) -1) {
	debug(50, 0) ("storeDiskdInit: shmat: %s\n", xstrerror());
	fatal("shmat failed");
    }
    diskdinfo->shm.inuse_map = xcalloc((diskdinfo->shm.nbufs + 7) / 8, 1);
    diskd_stats.shmbuf_count += diskdinfo->shm.nbufs;
    for (i = 0; i < diskdinfo->shm.nbufs; i++) {
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
    x = ipcCreate(IPC_STREAM,
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
    
    commonUfsDirInit (sd);
    
    comm_quick_poll_required();
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
	    debug(47, 1) ("storeDiskdDirCallback: msgget returns %d\n",
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

void
storeDiskdDirIOUnlinkFile(char *path)
{
#if USE_UNLINKD
    unlinkdUnlink(path);
#elif USE_TRUNCATE
    truncate(path, 0);
#else
    unlink(path);
#endif
		
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
    for (i = 0; i < diskdinfo->shm.nbufs; i++) {
	if (CBIT_TEST(diskdinfo->shm.inuse_map, i))
	    continue;
	CBIT_SET(diskdinfo->shm.inuse_map, i);
	*shm_offset = i * SHMBUF_BLKSZ;
	buf = diskdinfo->shm.buf + (*shm_offset);
	break;
    }
    assert(buf);
    assert(buf >= diskdinfo->shm.buf);
    assert(buf < diskdinfo->shm.buf + (diskdinfo->shm.nbufs * SHMBUF_BLKSZ));
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
    assert(offset < diskdinfo->shm.nbufs * SHMBUF_BLKSZ);
    i = offset / SHMBUF_BLKSZ;
    assert(i < diskdinfo->shm.nbufs);
    assert(CBIT_TEST(diskdinfo->shm.inuse_map, i));
    CBIT_CLR(diskdinfo->shm.inuse_map, i);
    diskd_stats.shmbuf_count--;
}




/* ========== LOCAL FUNCTIONS ABOVE, GLOBAL FUNCTIONS BELOW ========== */

void
storeDiskdDirStats(SwapDir * SD, StoreEntry * sentry)
{
    diskdinfo_t *diskdinfo = SD->fsdata;
    commonUfsDirStats (SD, sentry);
    storeAppendPrintf(sentry, "Pending operations: %d\n", diskdinfo->away);
}

static void
storeDiskdDirParseQ1(SwapDir * sd, const char *name, const char *value, int reconfiguring)
{
    diskdinfo_t *diskdinfo = sd->fsdata;
    int old_magic1 = diskdinfo->magic1;
    diskdinfo->magic1 = atoi(value);
    if (!reconfiguring)
	return;
    if (old_magic1 < diskdinfo->magic1) {
       /*
	* This is because shm.nbufs is computed at startup, when
	* we call shmget().  We can't increase the Q1/Q2 parameters
	* beyond their initial values because then we might have
	* more "Q2 messages" than shared memory chunks, and this
	* will cause an assertion in storeDiskdShmGet().
	*/
       debug(3, 1) ("WARNING: cannot increase cache_dir '%s' Q1 value while Squid is running.\n", sd->path);
       diskdinfo->magic1 = old_magic1;
       return;
    }
    if (old_magic1 != diskdinfo->magic1)
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
    if (!reconfiguring)
       return;
    if (old_magic2 < diskdinfo->magic2) {
       /* See comments in Q1 function above */
       debug(3, 1) ("WARNING: cannot increase cache_dir '%s' Q2 value while Squid is running.\n", sd->path);
       diskdinfo->magic2 = old_magic2;
       return;
    }
    if (old_magic2 != diskdinfo->magic2)
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
    commonUfsDirDump (entry, s);
    dump_cachedir_options(entry, options, s);
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
    diskdinfo->commondata.l1 = l1;
    diskdinfo->commondata.l2 = l2;
    diskdinfo->commondata.swaplog_fd = -1;
    diskdinfo->commondata.map = NULL;	/* Debugging purposes */
    diskdinfo->commondata.suggest = 0;
    diskdinfo->commondata.io.storeDirUnlinkFile = storeDiskdDirIOUnlinkFile;
    diskdinfo->magic1 = 64;
    diskdinfo->magic2 = 72;
    sd->init = storeDiskdDirInit;
    sd->newfs = commonUfsDirNewfs;
    sd->dump = storeDiskdDirDump;
    sd->freefs = commonUfsDirFree;
    sd->dblcheck = commonUfsCleanupDoubleCheck;
    sd->statfs = storeDiskdDirStats;
    sd->maintainfs = commonUfsDirMaintain;
    sd->checkobj = storeDiskdDirCheckObj;
    sd->refobj = commonUfsDirRefObj;
    sd->unrefobj = commonUfsDirUnrefObj;
    sd->callback = storeDiskdDirCallback;
    sd->sync = storeDiskdDirSync;
    sd->obj.create = storeDiskdCreate;
    sd->obj.open = storeDiskdOpen;
    sd->obj.close = storeDiskdClose;
    sd->obj.read = storeDiskdRead;
    sd->obj.write = storeDiskdWrite;
    sd->obj.unlink = storeDiskdUnlink;
    sd->log.open = commonUfsDirOpenSwapLog;
    sd->log.close = commonUfsDirCloseSwapLog;
    sd->log.write = commonUfsDirSwapLog;
    sd->log.clean.start = commonUfsDirWriteCleanStart;
    sd->log.clean.nextentry = commonUfsDirCleanLogNextEntry;
    sd->log.clean.done = commonUfsDirWriteCleanDone;

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
    memPoolDestroy(&diskd_state_pool);
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
    debug(47, 1) ("diskd started\n");
    diskd_initialised = 1;
}
