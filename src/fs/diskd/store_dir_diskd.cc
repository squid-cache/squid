
/*
 * $Id: store_dir_diskd.cc,v 1.74 2002/12/27 10:26:37 robertc Exp $
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

#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>

#include "store_diskd.h"

#include "ufscommon.h"

#include "SwapDir.h"

diskd_stats_t diskd_stats;

static int diskd_initialised = 0;

static void storeDiskdStats(StoreEntry * sentry);

/* The only externally visible interface */
STSETUP storeFsSetup_diskd;



void
DiskdSwapDir::init()
{
    int x;
    int rfd;
    int ikey;
    const char *args[5];
    char skey1[32];
    char skey2[32];
    char skey3[32];
    DiskdIO *DIO = dynamic_cast<DiskdIO *>(IO);

    ikey = (getpid() << 10) + (index << 2);
    ikey &= 0x7fffffff;
    DIO->smsgid = msgget((key_t) ikey, 0700 | IPC_CREAT);
    if (DIO->smsgid < 0) {
	debug(50, 0) ("storeDiskdInit: msgget: %s\n", xstrerror());
	fatal("msgget failed");
    }
    DIO->rmsgid = msgget((key_t) (ikey + 1), 0700 | IPC_CREAT);
    if (DIO->rmsgid < 0) {
	debug(50, 0) ("storeDiskdInit: msgget: %s\n", xstrerror());
	fatal("msgget failed");
    }
    DIO->shm.init(ikey, DIO->magic2);
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
	&DIO->wfd);
    if (x < 0)
	fatalf("execl: %s", Config.Program.diskd);
    if (rfd != DIO->wfd)
	comm_close(rfd);
    fd_note(DIO->wfd, "squid -> diskd");
    commSetTimeout(DIO->wfd, -1, NULL, NULL);
    commSetNonBlocking(DIO->wfd);
    
    UFSSwapDir::init();
    
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
void
DiskdSwapDir::sync()
{
    static time_t lastmsg = 0;
    DiskdIO *DIO = dynamic_cast<DiskdIO *>(IO);
    while (DIO->away > 0) {
	if (squid_curtime > lastmsg) {
	    debug(47, 1) ("storeDiskdDirSync: %d messages away\n",
		DIO->away);
	    lastmsg = squid_curtime;
	}
	callback();
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
DiskdSwapDir::callback()
{
    diomsg M;
    int x;
    int retval = 0;

    DiskdIO *DIO = dynamic_cast<DiskdIO *>(IO);
    if (DIO->away >= DIO->magic2) {
	diskd_stats.block_queue_len++;
	retval = 1;		/* We might not have anything to do, but our queue
				 * is full.. */
    }
    if (diskd_stats.sent_count - diskd_stats.recv_count >
	diskd_stats.max_away) {
	diskd_stats.max_away = diskd_stats.sent_count - diskd_stats.recv_count;
    }
    while (1) {
#ifdef	ALWAYS_ZERO_BUFFERS
	memset(&M, '\0', sizeof(M));
#endif
	x = msgrcv(DIO->rmsgid, &M, msg_snd_rcv_sz, 0, IPC_NOWAIT);
	if (x < 0)
	    break;
	else if (x != msg_snd_rcv_sz) {
	    debug(47, 1) ("storeDiskdDirCallback: msgget returns %d\n",
		x);
	    break;
	}
	diskd_stats.recv_count++;
	--DIO->away;
	storeDiskdHandle(&M);
	retval = 1;		/* Return that we've actually done some work */
	if (M.shm_offset > -1)
	    DIO->shm.put ((off_t) M.shm_offset);
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
DiskdSwapDir::canStore(StoreEntry const &e)const
{
    if (IO->shedLoad())
	return -1;
    return IO->load();
}

void
DiskdSwapDir::unlinkFile(char const *path)
{
#if USE_UNLINKD
    unlinkdUnlink(path);
#elif USE_TRUNCATE
    truncate(path, 0);
#else
    unlink(path);
#endif
		
}

/* ========== LOCAL FUNCTIONS ABOVE, GLOBAL FUNCTIONS BELOW ========== */

void
DiskdSwapDir::statfs(StoreEntry & sentry)const
{
    UFSSwapDir::statfs (sentry);
    DiskdIO *DIO = dynamic_cast<DiskdIO *>(IO);
    storeAppendPrintf(&sentry, "Pending operations: %d\n", DIO->away);
}

static void
storeDiskdDirParseQ1(SwapDir * sd, const char *name, const char *value, int reconfiguring)
{
    DiskdIO *IO = dynamic_cast<DiskdIO *>(((DiskdSwapDir *)sd)->IO);
    int old_magic1 = IO->magic1;
    IO->magic1 = atoi(value);
    if (!reconfiguring)
	return;
    if (old_magic1 < IO->magic1) {
       /*
	* This is because shm.nbufs is computed at startup, when
	* we call shmget().  We can't increase the Q1/Q2 parameters
	* beyond their initial values because then we might have
	* more "Q2 messages" than shared memory chunks, and this
	* will cause an assertion in storeDiskdShmGet().
	*/
       debug(3, 1) ("WARNING: cannot increase cache_dir '%s' Q1 value while Squid is running.\n", sd->path);
       IO->magic1 = old_magic1;
       return;
    }
    if (old_magic1 != IO->magic1)
	debug(3, 1) ("cache_dir '%s' new Q1 value '%d'\n",
	    sd->path, IO->magic1);
}

static void
storeDiskdDirDumpQ1(StoreEntry * e, const char *option, SwapDir const * sd)
{
    DiskdIO *IO = dynamic_cast<DiskdIO *>(((DiskdSwapDir *)sd)->IO);
    storeAppendPrintf(e, " Q1=%d", IO->magic1);
}

static void
storeDiskdDirParseQ2(SwapDir * sd, const char *name, const char *value, int reconfiguring)
{
    DiskdIO *IO = dynamic_cast<DiskdIO *>(((DiskdSwapDir *)sd)->IO);
    assert (IO);
    int old_magic2 = IO->magic2;
    IO->magic2 = atoi(value);
    if (!reconfiguring)
       return;
    if (old_magic2 < IO->magic2) {
       /* See comments in Q1 function above */
       debug(3, 1) ("WARNING: cannot increase cache_dir '%s' Q2 value while Squid is running.\n", sd->path);
       IO->magic2 = old_magic2;
       return;
    }
    if (old_magic2 != IO->magic2)
	debug(3, 1) ("cache_dir '%s' new Q2 value '%d'\n",
	    sd->path, IO->magic2);
}

static void
storeDiskdDirDumpQ2(StoreEntry * e, const char *option, SwapDir const * sd)
{
    DiskdIO *IO = dynamic_cast<DiskdIO *>(((DiskdSwapDir *)sd)->IO);
    storeAppendPrintf(e, " Q2=%d", IO->magic2);
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
void
DiskdSwapDir::reconfigure(int anIndex, char *aPath)
{
    UFSSwapDir::reconfigure (anIndex, aPath);

    parse_cachedir_options(this, options, 1);
}

void
DiskdSwapDir::dump(StoreEntry & entry)const
{
    UFSSwapDir::dump (entry);
    dump_cachedir_options(&entry, options, this);
}

/*
 * storeDiskdDirParse
 *
 * Called when a *new* fs is being setup.
 */
void
DiskdSwapDir::parse(int anIndex, char *aPath)
{
    UFSSwapDir::parse(anIndex, aPath);

    parse_cachedir_options(this, options, 0);
}

/*
 * Initial setup / end destruction
 */
static void
storeDiskdDirDone(void)
{
    diskd_initialised = 0;
}

static SwapDir *
storeDiskdNew(void)
{
    DiskdSwapDir *result = new DiskdSwapDir;
    result->IO = new DiskdIO;
    return result;
}

void
storeFsSetup_diskd(storefs_entry_t * storefs)
{
    assert(!diskd_initialised);
    storefs->donefunc = storeDiskdDirDone;
    storefs->newfunc = storeDiskdNew;
    memset(&diskd_stats, '\0', sizeof(diskd_stats));
    cachemgrRegister("diskd", "DISKD Stats", storeDiskdStats, 0, 1);
    debug(47, 1) ("diskd started\n");
    diskd_initialised = 1;
}
