
/*
 * $Id: store_io_diskd.cc,v 1.35 2003/07/29 11:34:57 robertc Exp $
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
 */

#include "config.h"
#include "squid.h"
#include "Store.h"

#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>

#include "store_diskd.h"
#include "SwapDir.h"

size_t DiskdIO::nextInstanceID (0);

static int storeDiskdSend(int, DiskdIO *, int, StoreIOState::Pointer, int, int, off_t);
static int storeDiskdSend(int, DiskdIO *, int, DiskdFile *, int, int, off_t);

/* === PUBLIC =========================================================== */
DiskdIO::DiskdIO() : away (0), magic1(64), magic2(72), instanceID(newInstance())
{}

size_t
DiskdIO::newInstance()
{
    return ++nextInstanceID;
}

bool
DiskdIO::shedLoad()
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
DiskdIO::load()
{
    /* Calculate the storedir load relative to magic2 on a scale of 0 .. 1000 */
    /* the parse function guarantees magic2 is positivie */
    return away * 1000 / magic2;
}

void
DiskdIO::deleteSelf() const
{
    /* do nothing, we use a single instance */
}

void
DiskdIO::openFailed()
{
    diskd_stats.open_fail_queue_len++;
}

StoreIOState::Pointer
DiskdIO::createState(SwapDir *SD, StoreEntry *e, STIOCB * callback, void *callback_data) const
{
    return new UFSStoreState (SD, e, callback, callback_data);
}

DiskFile::Pointer
DiskdIO::newFile (char const *path)
{
    return new DiskdFile (path, this);
}


void
DiskdIO::unlinkFile(char const *path)
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

    x = storeDiskdSend(_MQD_UNLINK,
                       this,
                       0,
                       (StoreIOState::Pointer )NULL,
                       0,
                       0,
                       shm_offset);

    if (x < 0) {
        debug(79, 1) ("storeDiskdSend UNLINK: %s\n", xstrerror());
        ::unlink(buf);		/* XXX EWW! */
        shm.put (shm_offset);
    }

    diskd_stats.unlink.ops++;
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

CBDATA_CLASS_INIT(DiskdFile);

void *
DiskdFile::operator new (size_t)
{
    CBDATA_INIT_TYPE(DiskdFile);
    DiskdFile *result = cbdataAlloc(DiskdFile);
    /* Mark result as being owned - we want the refcounter to do the delete
     * call */
    cbdataReference(result);
    debug (79,3)("diskdFile with base %p allocating\n", result);
    return result;
}

void
DiskdFile::operator delete (void *address)
{
    debug (79,3)("diskdFile with base %p deleting\n",address);
    DiskdFile *t = static_cast<DiskdFile *>(address);
    cbdataFree(address);
    /* And allow the memory to be freed */
    cbdataReferenceDone (t);
}

void
DiskdFile::deleteSelf() const {delete this;}

DiskdFile::DiskdFile (char const *aPath, DiskdIO *anIO) : errorOccured (false), IO(anIO),
        inProgressIOs (0)
{
    assert (aPath);
    debug (79,3)("DiskdFile::DiskdFile: %s\n", aPath);
    path_ = xstrdup (aPath);
    id = diskd_stats.sio_id++;
}

DiskdFile::~DiskdFile()
{
    assert (inProgressIOs == 0);
    safe_free (path_);
}

void
DiskdFile::open (int flags, mode_t aMode, IORequestor::Pointer callback)
{
    debug (79,3)("DiskdFile::open: %p opening for %p\n", this, callback.getRaw());
    assert (ioRequestor.getRaw() == NULL);
    ioRequestor = callback;
    assert (callback.getRaw());
    mode = flags;
    off_t shm_offset;
    char *buf = (char *)IO->shm.get(&shm_offset);
    xstrncpy(buf, path_, SHMBUF_BLKSZ);
    ioAway();
    int x = storeDiskdSend(_MQD_OPEN,
                           IO,
                           id,
                           this,
                           strlen(buf) + 1,
                           mode,
                           shm_offset);

    if (x < 0) {
        ioCompleted();
        errorOccured = true;
        IO->shm.put (shm_offset);
        ioRequestor->ioCompletedNotification();
        ioRequestor = NULL;
    }

    diskd_stats.open.ops++;
}

void
DiskdFile::create (int flags, mode_t aMode, IORequestor::Pointer callback)
{
    debug (79,3)("DiskdFile::create: %p creating for %p\n", this, callback.getRaw());
    assert (ioRequestor.getRaw() == NULL);
    ioRequestor = callback;
    assert (callback.getRaw());
    mode = flags;
    off_t shm_offset;
    char *buf = (char *)IO->shm.get(&shm_offset);
    xstrncpy(buf, path_, SHMBUF_BLKSZ);
    ioAway();
    int x = storeDiskdSend(_MQD_CREATE,
                           IO,
                           id,
                           this,
                           strlen(buf) + 1,
                           mode,
                           shm_offset);

    if (x < 0) {
        ioCompleted();
        errorOccured = true;
        IO->shm.put (shm_offset);
        debug(79, 1) ("storeDiskdSend CREATE: %s\n", xstrerror());
        notifyClient();
        ioRequestor = NULL;
        return;
    }

    diskd_stats.create.ops++;
}

void
DiskdFile::read(char *buf, off_t offset, size_t size)
{
    assert (ioRequestor.getRaw() != NULL);
    off_t shm_offset;
    char *rbuf = (char *)IO->shm.get(&shm_offset);
    assert(rbuf);
    ioAway();
    int x = storeDiskdSend(_MQD_READ,
                           IO,
                           id,
                           this,
                           (int) size,
                           (int) offset,
                           shm_offset);

    if (x < 0) {
        ioCompleted();
        errorOccured = true;
        IO->shm.put (shm_offset);
        debug(79, 1) ("storeDiskdSend READ: %s\n", xstrerror());
        notifyClient();
        ioRequestor = NULL;
        return;
    }

    diskd_stats.read.ops++;
}

void
DiskdFile::close()
{
    debug (79,3)("DiskdFile::close: %p closing for %p\n", this, ioRequestor.getRaw());
    assert (ioRequestor.getRaw());
    ioAway();
    int x = storeDiskdSend(_MQD_CLOSE,
                           IO,
                           id,
                           this,
                           0,
                           0,
                           -1);

    if (x < 0) {
        ioCompleted();
        errorOccured = true;
        debug(79, 1) ("storeDiskdSend CLOSE: %s\n", xstrerror());
        notifyClient();
        ioRequestor = NULL;
        return;
    }

    diskd_stats.close.ops++;
}

bool
DiskdFile::error() const
{
    return errorOccured;
}

bool
DiskdFile::canRead() const
{
    return !error();
}

bool
DiskdFile::canNotifyClient() const
{
    if (!ioRequestor.getRaw()) {
        debug (79,3)("DiskdFile::canNotifyClient: No ioRequestor to notify\n");
        return false;
    }

    return true;
}

void
DiskdFile::notifyClient()
{
    if (!canNotifyClient()) {
        return;
    }

    ioRequestor->ioCompletedNotification();
}

void
DiskdFile::completed(diomsg *M)
{
    assert (M->newstyle);

    switch (M->mtype) {

    case _MQD_OPEN:
        openDone(M);
        break;

    case _MQD_CREATE:
        createDone(M);
        break;

    case _MQD_CLOSE:
        closeDone(M);
        break;

    case _MQD_READ:
        readDone(M);
        break;

    case _MQD_WRITE:
        writeDone(M);
        break;

    case _MQD_UNLINK:
        assert (0);
        break;

    default:
        assert(0);
        break;
    }
}

void
DiskdFile::openDone(diomsg *M)
{
    statCounter.syscalls.disk.opens++;
    debug(79, 3) ("storeDiskdOpenDone: status %d\n", M->status);
    assert (FILE_MODE(mode) == O_RDONLY);

    if (M->status < 0) {
        diskd_stats.open.fail++;
        errorOccured = true;
    } else {
        diskd_stats.open.success++;
    }

    ioCompleted();
    notifyClient();
}

void
DiskdFile::createDone(diomsg *M)
{
    statCounter.syscalls.disk.opens++;
    debug(79, 3) ("storeDiskdCreateDone: status %d\n", M->status);

    if (M->status < 0) {
        diskd_stats.create.fail++;
        errorOccured = true;
    } else {
        diskd_stats.create.success++;
    }

    ioCompleted();
    notifyClient();
}

void
DiskdFile::write(char const *buf, size_t size, off_t offset, FREE *free_func)
{
    debug(79, 3) ("DiskdFile::write: this %p , buf %p, off %ld, len %d\n", this, buf, offset, size);
    off_t shm_offset;
    char *sbuf = (char *)IO->shm.get(&shm_offset);
    xmemcpy(sbuf, buf, size);

    if (free_func)
        free_func(const_cast<char *>(buf));

    ioAway();

    int x = storeDiskdSend(_MQD_WRITE,
                           IO,
                           id,
                           this,
                           (int) size,
                           (int) offset,
                           shm_offset);

    if (x < 0) {
        ioCompleted();
        errorOccured = true;
        debug(79, 1) ("storeDiskdSend WRITE: %s\n", xstrerror());
        IO->shm.put (shm_offset);
        notifyClient();
        ioRequestor = NULL;
        return;
    }

    diskd_stats.write.ops++;
}


/*  === STATIC =========================================================== */

void
DiskdFile::ioAway()
{
    ++inProgressIOs;
}

void
DiskdFile::ioCompleted()
{
    --inProgressIOs;
}

void
DiskdFile::closeDone(diomsg * M)
{
    statCounter.syscalls.disk.closes++;
    debug(79, 3) ("DiskdFile::closeDone: status %d\n", M->status);

    if (M->status < 0) {
        diskd_stats.close.fail++;
        errorOccured = true;
    } else {
        diskd_stats.close.success++;
    }

    ioCompleted();

    if (canNotifyClient())
        ioRequestor->closeCompleted();

    ioRequestor = NULL;
}

void
DiskdFile::readDone(diomsg * M)
{
    statCounter.syscalls.disk.reads++;
    debug(79, 3) ("DiskdFile::readDone: status %d\n", M->status);

    if (M->status < 0) {
        diskd_stats.read.fail++;
        ioCompleted();
        errorOccured = true;
        ioRequestor->readCompleted(NULL, -1, DISK_ERROR);
        return;
    }

    diskd_stats.read.success++;

    ioCompleted();
    ioRequestor->readCompleted (IO->shm.buf + M->shm_offset,  M->status, DISK_OK);
}

void
DiskdFile::writeDone(diomsg *M)
{
    statCounter.syscalls.disk.writes++;
    debug(79, 3) ("storeDiskdWriteDone: status %d\n", M->status);

    if (M->status < 0) {
        errorOccured = true;
        diskd_stats.write.fail++;
        ioCompleted();
        ioRequestor->writeCompleted (DISK_ERROR,0);
        return;
    }

    diskd_stats.write.success++;
    ioCompleted();
    ioRequestor->writeCompleted (DISK_OK,M->status);
}

bool
DiskdFile::ioInProgress()const
{
    return inProgressIOs != 0;
}

void
DiskdIO::unlinkDone(diomsg * M)
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
DiskdIO::storeDiskdHandle(diomsg * M)
{
    if (!cbdataReferenceValid (M->callback_data)) {
        debug(79, 3) ("storeDiskdHandle: Invalid callback_data %p\n",
                      M->callback_data);
        cbdataReferenceDone (M->callback_data);
        return;
    }


    if (M->newstyle) {
        DiskdFile *theFile = (DiskdFile *)M->callback_data;
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
storeDiskdSend(int mtype, DiskdIO *IO, int id, DiskdFile *theFile, int size, int offset, off_t shm_offset)
{
    int x;
    diomsg M;
    static int send_errors = 0;
    static int last_seq_no = 0;
    static int seq_no = 0;
    M.mtype = mtype;
    M.callback_data = cbdataReference(theFile);
    M.size = size;
    M.offset = offset;
    M.status = -1;
    M.shm_offset = (int) shm_offset;
    M.id = id;
    M.seq_no = ++seq_no;
    M.newstyle = true;

    if (M.seq_no < last_seq_no)
        debug(79, 1) ("WARNING: sequencing out of order\n");

    x = msgsnd(IO->smsgid, &M, msg_snd_rcv_sz, IPC_NOWAIT);

    last_seq_no = M.seq_no;

    if (0 == x) {
        diskd_stats.sent_count++;
        IO->away++;
    } else {
        debug(79, 1) ("storeDiskdSend: msgsnd: %s\n", xstrerror());
        cbdataReferenceDone(M.callback_data);
        assert(++send_errors < 100);
        IO->shm.put (shm_offset);
    }

    /*
     * We have to drain the queue here if necessary.  If we don't,
     * then we can have a lot of messages in the queue (probably
     * up to 2*magic1) and we can run out of shared memory buffers.
     */
    /*
     * Note that we call storeDirCallback (for all SDs), rather
     * than storeDiskdDirCallback for just this SD, so that while
     * we're "blocking" on this SD we can also handle callbacks
     * from other SDs that might be ready.
     */
    while (IO->away > IO->magic2) {

        struct timeval delay = {0, 1};

        select(0, NULL, NULL, NULL, &delay);
        storeDirCallback();

        if (delay.tv_usec < 1000000)
            delay.tv_usec <<= 1;
    }

    return x;
}

static int
storeDiskdSend(int mtype, DiskdIO *IO, int id, StoreIOState::Pointer sio, int size, int offset, off_t shm_offset)
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

    x = msgsnd(IO->smsgid, &M, msg_snd_rcv_sz, IPC_NOWAIT);

    last_seq_no = M.seq_no;

    if (0 == x) {
        diskd_stats.sent_count++;
        IO->away++;
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
     * Note that we call storeDirCallback (for all SDs), rather
     * than storeDiskdDirCallback for just this SD, so that while
     * we're "blocking" on this SD we can also handle callbacks
     * from other SDs that might be ready.
     */
    while (IO->away > IO->magic2) {

        struct timeval delay = {0, 1};

        select(0, NULL, NULL, NULL, &delay);
        storeDirCallback();

        if (delay.tv_usec < 1000000)
            delay.tv_usec <<= 1;
    }

    return x;
}

SwapDirOption *
DiskdIO::getOptionTree() const
{
    SwapDirOptionVector *result = new SwapDirOptionVector;
    result->options.push_back(new SwapDirOptionAdapter<DiskdIO>(*const_cast<DiskdIO *>(this), &DiskdIO::optionQ1Parse, &DiskdIO::optionQ1Dump));
    result->options.push_back(new SwapDirOptionAdapter<DiskdIO>(*const_cast<DiskdIO *>(this), &DiskdIO::optionQ2Parse, &DiskdIO::optionQ2Dump));
    return result;
}

bool
DiskdIO::optionQ1Parse(const char *name, const char *value, int reconfiguring)
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
DiskdIO::optionQ1Dump(StoreEntry * e) const
{
    storeAppendPrintf(e, " Q1=%d", magic1);
}

bool
DiskdIO::optionQ2Parse(const char *name, const char *value, int reconfiguring)
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
DiskdIO::optionQ2Dump(StoreEntry * e) const
{
    storeAppendPrintf(e, " Q2=%d", magic2);
}

void
DiskdIO::init()
{
    int x;
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
    x = ipcCreate(IPC_STREAM,
                  Config.Program.diskd,
                  args,
                  "diskd",
                  &rfd,
                  &wfd);

    if (x < 0)
        fatalf("execl: %s", Config.Program.diskd);

    if (rfd != wfd)
        comm_close(rfd);

    fd_note(wfd, "squid -> diskd");

    commSetTimeout(wfd, -1, NULL, NULL);

    commSetNonBlocking(wfd);

    comm_quick_poll_required();
}

/*
 * Sync any pending data. We just sit around and read the queue
 * until the data has finished writing.
 */
void
DiskdIO::sync()
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
DiskdIO::callback()
{
    diomsg M;
    int x;
    int retval = 0;

    DiskdIO *DIO = this;//dynamic_cast<DiskdIO *>(IO);

    if (DIO->away >= DIO->magic2) {
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
        DIO->storeDiskdHandle(&M);
        retval = 1;		/* Return that we've actually done some work */

        if (M.shm_offset > -1)
            DIO->shm.put ((off_t) M.shm_offset);
    }

    return retval;
}

void
DiskdIO::statfs(StoreEntry & sentry)const
{
    storeAppendPrintf(&sentry, "Pending operations: %d\n", away);
}

DiskdIOModule::DiskdIOModule() : initialised(false) {}

DiskdIOModule &
DiskdIOModule::GetInstance()
{
    if (!Instance)
        Instance = new DiskdIOModule;

    return *Instance;
}

void
DiskdIOModule::init()
{
    /* We may be reused - for instance in coss - eventually.
     * When we do, we either need per-using-module stats (
     * no singleton pattern), or we need to refcount the 
     * initialisation level and handle multiple clients.
     * RBC - 20030718.
     */
    assert(!initialised);
    memset(&diskd_stats, '\0', sizeof(diskd_stats));
    cachemgrRegister("diskd", "DISKD Stats", storeDiskdStats, 0, 1);

    debug(47, 1) ("diskd started\n");
    initialised = true;
}

void
DiskdIOModule::shutdown()
{
    initialised = false;
}

UFSStrategy *
DiskdIOModule::createSwapDirIOStrategy()
{
    return new DiskdIO;
}

DiskdIOModule *DiskdIOModule::Instance = NULL;

diskd_stats_t diskd_stats;

void
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
