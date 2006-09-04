
/*
 * $Id: DiskdIOStrategy.cc,v 1.5 2006/09/03 18:47:18 serassio Exp $
 *
 * DEBUG: section 79    Squid-side DISKD I/O functions.
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"

#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include "DiskdIOStrategy.h"
#include "ConfigOption.h"
#include "DiskIO/DiskFile.h"
#include "DiskdFile.h"
#include "diomsg.h"
/* for statfs */
#include "Store.h"
#include "SquidTime.h"

diskd_stats_t diskd_stats;

size_t DiskdIOStrategy::nextInstanceID (0);
const int diomsg::msg_snd_rcv_sz = sizeof(diomsg) - sizeof(mtyp_t);

size_t
DiskdIOStrategy::newInstance()
{
    return ++nextInstanceID;
}

bool
DiskdIOStrategy::shedLoad()
{
    /*
     * Fail on open() if there are too many requests queued.
     */

    if (away > magic1) {
        debug(79, 3) ("storeDiskdIO::shedLoad: Shedding, too many requests away\n");

        return true;
    }

    return false;
}

int
DiskdIOStrategy::load()
{
    /* Calculate the storedir load relative to magic2 on a scale of 0 .. 1000 */
    /* the parse function guarantees magic2 is positivie */
    return away * 1000 / magic2;
}

void
DiskdIOStrategy::openFailed()
{
    diskd_stats.open_fail_queue_len++;
}

DiskFile::Pointer
DiskdIOStrategy::newFile(char const *path)
{
    if (shedLoad()) {
        openFailed();
        return NULL;
    }

    return new DiskdFile (path, this);
}

DiskdIOStrategy::DiskdIOStrategy() : magic1(64), magic2(72), away(0) , smsgid(-1), rmsgid(-1), wfd(-1) , instanceID(newInstance())
{}

void
DiskdIOStrategy::unlinkFile(char const *path)
{
    if (shedLoad()) {
        /* Damn, we need to issue a sync unlink here :( */
        debug(79, 2) ("storeDiskUnlink: Out of queue space, sync unlink\n");
#if USE_UNLINKD

        unlinkdUnlink(path);
#elif USE_TRUNCATE

        truncate(path, 0);
#else

        unlink(path);
#endif

        return;
    }

    /* We can attempt a diskd unlink */
    int x;

    off_t shm_offset;

    char *buf;

    buf = (char *)shm.get(&shm_offset);

    xstrncpy(buf, path, SHMBUF_BLKSZ);

    x = send(_MQD_UNLINK,
             0,
             (StoreIOState::Pointer )NULL,
             0,
             0,
             shm_offset);

    if (x < 0) {
        debug(79, 1) ("storeDiskdSend UNLINK: %s\n", xstrerror());
        ::unlink(buf);		/* XXX EWW! */
        //        shm.put (shm_offset);
    }

    diskd_stats.unlink.ops++;
}

void
DiskdIOStrategy::init()
{
    int pid;
    void * hIpc;
    int rfd;
    int ikey;
    const char *args[5];
    char skey1[32];
    char skey2[32];
    char skey3[32];

    ikey = (getpid() << 10) + (instanceID << 2);
    ikey &= 0x7fffffff;
    smsgid = msgget((key_t) ikey, 0700 | IPC_CREAT);

    if (smsgid < 0) {
        debug(50, 0) ("storeDiskdInit: msgget: %s\n", xstrerror());
        fatal("msgget failed");
    }

    rmsgid = msgget((key_t) (ikey + 1), 0700 | IPC_CREAT);

    if (rmsgid < 0) {
        debug(50, 0) ("storeDiskdInit: msgget: %s\n", xstrerror());
        fatal("msgget failed");
    }

    shm.init(ikey, magic2);
    snprintf(skey1, 32, "%d", ikey);
    snprintf(skey2, 32, "%d", ikey + 1);
    snprintf(skey3, 32, "%d", ikey + 2);
    args[0] = "diskd";
    args[1] = skey1;
    args[2] = skey2;
    args[3] = skey3;
    args[4] = NULL;
    pid = ipcCreate(IPC_STREAM,
                    Config.Program.diskd,
                    args,
                    "diskd",
                    &rfd,
                    &wfd,
                    &hIpc);

    if (pid < 0)
        fatalf("execl: %s", Config.Program.diskd);

    if (rfd != wfd)
        comm_close(rfd);

    fd_note(wfd, "squid -> diskd");

    commSetTimeout(wfd, -1, NULL, NULL);

    commSetNonBlocking(wfd);

    comm_quick_poll_required();
}

/*
 * SHM manipulation routines
 */
void
SharedMemory::put (off_t offset)
{
    int i;
    assert(offset >= 0);
    assert(offset < nbufs * SHMBUF_BLKSZ);
    i = offset / SHMBUF_BLKSZ;
    assert(i < nbufs);
    assert(CBIT_TEST(inuse_map, i));
    CBIT_CLR(inuse_map, i);
    --diskd_stats.shmbuf_count;
}

void *

SharedMemory::get
    (off_t * shm_offset)
{
    char *aBuf = NULL;
    int i;

    for (i = 0; i < nbufs; i++) {
        if (CBIT_TEST(inuse_map, i))
            continue;

        CBIT_SET(inuse_map, i);

        *shm_offset = i * SHMBUF_BLKSZ;

        aBuf = buf + (*shm_offset);

        break;
    }

    assert(aBuf);
    assert(aBuf >= buf);
    assert(aBuf < buf + (nbufs * SHMBUF_BLKSZ));
    diskd_stats.shmbuf_count++;

    if (diskd_stats.max_shmuse < diskd_stats.shmbuf_count)
        diskd_stats.max_shmuse = diskd_stats.shmbuf_count;

    return aBuf;
}

void
SharedMemory::init(int ikey, int magic2)
{
    nbufs = (int)(magic2 * 1.3);
    id = shmget((key_t) (ikey + 2),
                nbufs * SHMBUF_BLKSZ, 0600 | IPC_CREAT);

    if (id < 0) {
        debug(50, 0) ("storeDiskdInit: shmget: %s\n", xstrerror());
        fatal("shmget failed");
    }

    buf = (char *)shmat(id, NULL, 0);

    if (buf == (void *) -1) {
        debug(50, 0) ("storeDiskdInit: shmat: %s\n", xstrerror());
        fatal("shmat failed");
    }

    inuse_map = (char *)xcalloc((nbufs + 7) / 8, 1);
    diskd_stats.shmbuf_count += nbufs;

    for (int i = 0; i < nbufs; i++) {
        CBIT_SET(inuse_map, i);
        put (i * SHMBUF_BLKSZ);
    }
}

void
DiskdIOStrategy::unlinkDone(diomsg * M)
{
    debug(79, 3) ("storeDiskdUnlinkDone: file %s status %d\n",shm.buf + M->shm_offset,
                  M->status);
    statCounter.syscalls.disk.unlinks++;

    if (M->status < 0)
        diskd_stats.unlink.fail++;
    else
        diskd_stats.unlink.success++;
}

void
DiskdIOStrategy::handle(diomsg * M)
{
    if (!cbdataReferenceValid (M->callback_data)) {
        /* I.e. already closed file
         * - say when we have a error opening after
         *   a read was already queued
         */
        debug(79, 3) ("storeDiskdHandle: Invalid callback_data %p\n",
                      M->callback_data);
        cbdataReferenceDone (M->callback_data);
        return;
    }


    if (M->newstyle) {
        DiskdFile *theFile = (DiskdFile *)M->callback_data;
        theFile->RefCountDereference();
        theFile->completed (M);
    } else
        switch (M->mtype) {

        case _MQD_OPEN:

        case _MQD_CREATE:

        case _MQD_CLOSE:

        case _MQD_READ:

        case _MQD_WRITE:
            assert (0);
            break;

        case _MQD_UNLINK:
            unlinkDone(M);
            break;

        default:
            assert(0);
            break;
        }

    cbdataReferenceDone (M->callback_data);
}

int
DiskdIOStrategy::send(int mtype, int id, DiskdFile *theFile, int size, int offset, off_t shm_offset, RefCountable_ *requestor)
{
    int x;
    diomsg M;
    static int send_errors = 0;
    static int last_seq_no = 0;
    static int seq_no = 0;
    M.mtype = mtype;
    M.callback_data = cbdataReference(theFile);
    theFile->RefCountReference();
    M.requestor = requestor;

    if (requestor)
        requestor->RefCountReference();

    M.size = size;

    M.offset = offset;

    M.status = -1;

    M.shm_offset = (int) shm_offset;

    M.id = id;

    M.seq_no = ++seq_no;

    M.newstyle = true;

    if (M.seq_no < last_seq_no)
        debug(79, 1) ("WARNING: sequencing out of order\n");

    debugs (79,9, "sending with" << smsgid <<" " << &M << " " <<diomsg::msg_snd_rcv_sz << " " << IPC_NOWAIT);

    x = msgsnd(smsgid, &M, diomsg::msg_snd_rcv_sz, IPC_NOWAIT);

    last_seq_no = M.seq_no;

    if (0 == x) {
        diskd_stats.sent_count++;
        away++;
    } else {
        debug(79, 1) ("storeDiskdSend: msgsnd: %s\n", xstrerror());
        cbdataReferenceDone(M.callback_data);
        assert(++send_errors < 100);
        shm.put (shm_offset);
    }

    /*
     * We have to drain the queue here if necessary.  If we don't,
     * then we can have a lot of messages in the queue (probably
     * up to 2*magic1) and we can run out of shared memory buffers.
     */
    /*
     * Note that we call Store::Root().callbackk (for all SDs), rather
     * than callback for just this SD, so that while
     * we're "blocking" on this SD we can also handle callbacks
     * from other SDs that might be ready.
     */

    struct timeval delay = {0, 1};

    while (away > magic2) {
        select(0, NULL, NULL, NULL, &delay);
        Store::Root().callback();

        if (delay.tv_usec < 1000000)
            delay.tv_usec <<= 1;
    }

    return x;
}

int
DiskdIOStrategy::send(int mtype, int id, StoreIOState::Pointer sio, int size, int offset, off_t shm_offset)
{
    int x;
    diomsg M;
    static int send_errors = 0;
    static int last_seq_no = 0;
    static int seq_no = 0;
    M.mtype = mtype;
    M.callback_data = cbdataReference(sio.getRaw());
    M.size = size;
    M.offset = offset;
    M.status = -1;
    M.shm_offset = (int) shm_offset;
    M.id = id;
    M.seq_no = ++seq_no;
    M.newstyle = false;

    if (M.seq_no < last_seq_no)
        debug(79, 1) ("WARNING: sequencing out of order\n");

    x = msgsnd(smsgid, &M, diomsg::msg_snd_rcv_sz, IPC_NOWAIT);

    last_seq_no = M.seq_no;

    if (0 == x) {
        diskd_stats.sent_count++;
        away++;
    } else {
        debug(79, 1) ("storeDiskdSend: msgsnd: %s\n", xstrerror());
        cbdataReferenceDone(M.callback_data);
        assert(++send_errors < 100);
    }

    /*
     * We have to drain the queue here if necessary.  If we don't,
     * then we can have a lot of messages in the queue (probably
     * up to 2*magic1) and we can run out of shared memory buffers.
     */
    /*
     * Note that we call Store::Root().callbackk (for all SDs), rather
     * than callback for just this SD, so that while
     * we're "blocking" on this SD we can also handle callbacks
     * from other SDs that might be ready.
     */

    struct timeval delay = {0, 1};

    while (away > magic2) {
        select(0, NULL, NULL, NULL, &delay);
        Store::Root().callback();

        if (delay.tv_usec < 1000000)
            delay.tv_usec <<= 1;
    }

    return x;
}

ConfigOption *
DiskdIOStrategy::getOptionTree() const
{
    ConfigOptionVector *result = new ConfigOptionVector;
    result->options.push_back(new ConfigOptionAdapter<DiskdIOStrategy>(*const_cast<DiskdIOStrategy *>(this), &DiskdIOStrategy::optionQ1Parse, &DiskdIOStrategy::optionQ1Dump));
    result->options.push_back(new ConfigOptionAdapter<DiskdIOStrategy>(*const_cast<DiskdIOStrategy *>(this), &DiskdIOStrategy::optionQ2Parse, &DiskdIOStrategy::optionQ2Dump));
    return result;
}

bool
DiskdIOStrategy::optionQ1Parse(const char *name, const char *value, int reconfiguring)
{
    if (strcmp(name, "Q1") != 0)
        return false;

    int old_magic1 = magic1;

    magic1 = atoi(value);

    if (!reconfiguring)
        return true;

    if (old_magic1 < magic1) {
        /*
        * This is because shm.nbufs is computed at startup, when
        * we call shmget().  We can't increase the Q1/Q2 parameters
        * beyond their initial values because then we might have
        * more "Q2 messages" than shared memory chunks, and this
        * will cause an assertion in storeDiskdShmGet().
        */
        /* TODO: have DiskdIO hold a link to the swapdir, to allow detailed reporting again */
        debug(3, 1) ("WARNING: cannot increase cache_dir Q1 value while Squid is running.\n");
        magic1 = old_magic1;
        return true;
    }

    if (old_magic1 != magic1)
        debug(3, 1) ("cache_dir new Q1 value '%d'\n",
                     magic1);

    return true;
}

void
DiskdIOStrategy::optionQ1Dump(StoreEntry * e) const
{
    storeAppendPrintf(e, " Q1=%d", magic1);
}

bool
DiskdIOStrategy::optionQ2Parse(const char *name, const char *value, int reconfiguring)
{
    if (strcmp(name, "Q2") != 0)
        return false;

    int old_magic2 = magic2;

    magic2 = atoi(value);

    if (!reconfiguring)
        return true;

    if (old_magic2 < magic2) {
        /* See comments in Q1 function above */
        debug(3, 1) ("WARNING: cannot increase cache_dir Q2 value while Squid is running.\n");
        magic2 = old_magic2;
        return true;
    }

    if (old_magic2 != magic2)
        debug(3, 1) ("cache_dir new Q2 value '%d'\n",
                     magic2);

    return true;
}

void
DiskdIOStrategy::optionQ2Dump(StoreEntry * e) const
{
    storeAppendPrintf(e, " Q2=%d", magic2);
}

/*
 * Sync any pending data. We just sit around and read the queue
 * until the data has finished writing.
 */
void
DiskdIOStrategy::sync()
{
    static time_t lastmsg = 0;

    while (away > 0) {
        if (squid_curtime > lastmsg) {
            debug(47, 1) ("storeDiskdDirSync: %d messages away\n",
                          away);
            lastmsg = squid_curtime;
        }

        callback();
    }
}


/*
 * Handle callbacks. If we have more than magic2 requests away, we block
 * until the queue is below magic2. Otherwise, we simply return when we
 * don't get a message.
 */

int
DiskdIOStrategy::callback()
{
    diomsg M;
    int x;
    int retval = 0;

    if (away >= magic2) {
        diskd_stats.block_queue_len++;
        retval = 1;
        /* We might not have anything to do, but our queue
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

        x = msgrcv(rmsgid, &M, diomsg::msg_snd_rcv_sz, 0, IPC_NOWAIT);

        if (x < 0)
            break;
        else if (x != diomsg::msg_snd_rcv_sz) {
            debug(47, 1) ("storeDiskdDirCallback: msgget returns %d\n",
                          x);
            break;
        }

        diskd_stats.recv_count++;
        --away;
        handle(&M);
        retval = 1;		/* Return that we've actually done some work */

        if (M.shm_offset > -1)
            shm.put ((off_t) M.shm_offset);
    }

    return retval;
}

void
DiskdIOStrategy::statfs(StoreEntry & sentry)const
{
    storeAppendPrintf(&sentry, "Pending operations: %d\n", away);
}
