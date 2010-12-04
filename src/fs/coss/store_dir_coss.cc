#error COSS Support is not stable yet in Squid-3. Please do not use.
/*
 * $Id$
 * vim: set et :
 *
 * DEBUG: section 47    Store COSS Directory Routines
 * AUTHOR: Eric Stern
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
#include "CossSwapDir.h"
#include "Store.h"

#include "store_coss.h"
#include "event.h"
#include "fde.h"
#include "SwapDir.h"
#include "StoreSwapLogData.h"
#include "DiskIO/DiskIOModule.h"
#include "DiskIO/DiskIOStrategy.h"
#include "DiskIO/ReadRequest.h"
#include "ConfigOption.h"
#include "StoreFScoss.h"
#include "Parsing.h"

#define STORE_META_BUFSZ 4096

int n_coss_dirs = 0;
/* static int last_coss_pick_index = -1; */
MemAllocator *coss_index_pool = NULL;

typedef struct _RebuildState RebuildState;

struct _RebuildState {
    CossSwapDir *sd;
    int n_read;
    FILE *log;
    int speed;

    struct {
        unsigned int clean:1;
    } flags;

    struct _store_rebuild_data counts;
};

static char *storeCossDirSwapLogFile(SwapDir *, const char *);
static EVH storeCossRebuildFromSwapLog;
static StoreEntry *storeCossAddDiskRestore(CossSwapDir * SD, const cache_key * key,
        int file_number,
        uint64_t swap_file_sz,
        time_t expires,
        time_t timestamp,
        time_t lastref,
        time_t lastmod,
        u_int32_t refcount,
        u_int16_t flags,
        int clean);
static void storeCossDirRebuild(CossSwapDir * sd);
static void storeCossDirCloseTmpSwapLog(CossSwapDir * sd);
static FILE *storeCossDirOpenTmpSwapLog(CossSwapDir *, int *, int *);

static char *
storeCossDirSwapLogFile(SwapDir * sd, const char *ext)
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

void
CossSwapDir::openLog()
{
    char *logPath;
    logPath = storeCossDirSwapLogFile(this, NULL);
    swaplog_fd = file_open(logPath, O_WRONLY | O_CREAT | O_BINARY);

    if (swaplog_fd < 0) {
        debugs(47, 1, "" << logPath << ": " << xstrerror());
        fatal("storeCossDirOpenSwapLog: Failed to open swap log.");
    }

    debugs(47, 3, "Cache COSS Dir #" << index << " log opened on FD " << swaplog_fd);
}

void
CossSwapDir::closeLog()
{
    if (swaplog_fd < 0)	/* not open */
        return;

    file_close(swaplog_fd);

    debugs(47, 3, "Cache COSS Dir #" << index << " log closed on FD " << swaplog_fd);

    swaplog_fd = -1;
}

void
CossSwapDir::ioCompletedNotification()
{
    if (theFile->error()) {
        debugs(47, 1, "" << path << ": " << xstrerror());
        fatal("storeCossDirInit: Failed to open a COSS file.");
    }
}

void
CossSwapDir::closeCompleted()
{
    theFile = NULL;
}

void
CossSwapDir::readCompleted(const char *buf, int len, int errflag, RefCount<ReadRequest> aRequest)
{
    CossRead* cossRead= dynamic_cast<CossRead *>(aRequest.getRaw());
    assert (cossRead);
    StoreIOState::Pointer sio =  cossRead->sio;
    void *cbdata;
    StoreIOState::STRCB *callback = sio->read.callback;
    char *p;
    CossState *cstate = dynamic_cast<CossState *>(sio.getRaw());
    ssize_t rlen;

    debugs(79, 3, "storeCossReadDone: fileno " << sio->swap_filen << ", len " << len);
    cstate->flags.reading = 0;

    if (errflag) {
        StoreFScoss::GetInstance().stats.read.fail++;

        if (errflag > 0) {
            errno = errflag;
            debugs(79, 1, "storeCossReadDone: error: " << xstrerror());
        } else {
            debugs(79, 1, "storeCossReadDone: got failure (" << errflag << ")");
        }

        rlen = -1;
    } else {
        StoreFScoss::GetInstance().stats.read.success++;

        if (cstate->readbuffer == NULL) {
            cstate->readbuffer = (char *)xmalloc(cstate->st_size);
            p = storeCossMemPointerFromDiskOffset(storeCossFilenoToDiskOffset(sio->swap_filen),
                                                  NULL);
            xmemcpy(cstate->readbuffer, p, cstate->st_size);
        }

        sio->offset_ += len;
        xmemcpy(cstate->requestbuf, &cstate->readbuffer[cstate->requestoffset],
                cstate->requestlen);
        rlen = (size_t) cstate->requestlen;
    }

    assert(callback);
    sio->read.callback = NULL;

    if (cbdataReferenceValidDone(sio->read.callback_data, &cbdata))
        callback(cbdata, cstate->requestbuf, rlen, sio);
}

void
CossSwapDir::writeCompleted(int errflag, size_t len, RefCount<WriteRequest> writeRequest)
{
    CossWrite* cossWrite= dynamic_cast<CossWrite *>(writeRequest.getRaw());
    assert (cossWrite);

    debugs(79, 3, "storeCossWriteMemBufDone: buf " << cossWrite->membuf << ", len " << len);


    if (errflag) {
        StoreFScoss::GetInstance().stats.stripe_write.fail++;
        debugs(79, 1, "storeCossWriteMemBufDone: got failure (" << errflag << ")");
        debugs(79, 1, "size=" << cossWrite->membuf->diskend - cossWrite->membuf->diskstart);
    } else {
        StoreFScoss::GetInstance().stats.stripe_write.success++;
    }


    dlinkDelete(&cossWrite->membuf->node, &membufs);
    cbdataFree(cossWrite->membuf);
    StoreFScoss::GetInstance().stats.stripes--;
}

void
CossSwapDir::changeIO(DiskIOModule *module)
{
    DiskIOStrategy *anIO = module->createStrategy();
    safe_free(ioModule);
    ioModule = xstrdup(module->type());

    delete io;
    io = anIO;
    /* Change the IO Options */

    if (currentIOOptions == NULL)
        currentIOOptions = new ConfigOptionVector();

    if (currentIOOptions->options.size() > 3)
        delete currentIOOptions->options.pop_back();

    /* TODO: factor out these 4 lines */
    ConfigOption *ioOptions = NULL;

    if (io)
        ioOptions = io->getOptionTree();

    if (ioOptions)
        currentIOOptions->options.push_back(ioOptions);
}

bool
CossSwapDir::optionIOParse(char const *option, const char *value, int reconfiguring)
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
CossSwapDir::optionIODump(StoreEntry * e) const
{
    storeAppendPrintf(e, " IOEngine=%s", ioModule);
}

ConfigOption *
CossSwapDir::getOptionTree() const
{
    ConfigOption *parentResult = SwapDir::getOptionTree();

    if (currentIOOptions == NULL)
        currentIOOptions = new ConfigOptionVector();

    currentIOOptions->options.push_back(parentResult);

    currentIOOptions->options.push_back(new ConfigOptionAdapter<CossSwapDir>(*const_cast<CossSwapDir *>(this), &CossSwapDir::optionIOParse, &CossSwapDir::optionIODump));

    currentIOOptions->options.push_back(
        new ConfigOptionAdapter<CossSwapDir>(*const_cast<CossSwapDir *>(this),
                                             &CossSwapDir::optionBlockSizeParse,
                                             &CossSwapDir::optionBlockSizeDump));


    ConfigOption *ioOptions = NULL;

    if (io)
        ioOptions = io->getOptionTree();

    if (ioOptions)
        currentIOOptions->options.push_back(ioOptions);

    ConfigOption* result = currentIOOptions;

    currentIOOptions = NULL;

    return result;
}

void
CossSwapDir::init()
{
    /* FIXME: SwapDirs aren't refcounted. We call IORequestor calls, which
     * are refcounted. SO, we up our count once to avoid implicit delete's.
     */
    RefCountReference();
    io->init();
    openLog();
    storeCossDirRebuild(this);
    theFile = io->newFile(stripePath());
    theFile->open(O_RDWR | O_CREAT, 0644, this);

    ++n_coss_dirs;
    /*
     * fs.blksize is normally determined by calling statvfs() etc,
     * but we just set it here.  It is used in accounting the
     * total store size, and is reported in cachemgr 'storedir'
     * page.
     */
    fs.blksize = 1 << blksz_bits;
}

void
storeCossRemove(CossSwapDir * sd, StoreEntry * e)
{
    CossIndexNode *coss_node = (CossIndexNode *)e->repl.data;
    e->repl.data = NULL;
    dlinkDelete(&coss_node->node, &sd->cossindex);
    coss_index_pool->free(coss_node);
    sd->count -= 1;
}

void
storeCossAdd(CossSwapDir * sd, StoreEntry * e)
{
    CossIndexNode *coss_node = (CossIndexNode *)coss_index_pool->alloc();
    assert(!e->repl.data);
    e->repl.data = coss_node;
    dlinkAdd(e, &coss_node->node, &sd->cossindex);
    sd->count += 1;
}

static void
storeCossRebuildComplete(void *data)
{
    RebuildState *rb = (RebuildState *)data;
    CossSwapDir *sd = rb->sd;
    sd->startMembuf();
    StoreController::store_dirs_rebuilding--;
    storeCossDirCloseTmpSwapLog(rb->sd);
    storeRebuildComplete(&rb->counts);
    cbdataFree(rb);
}

static void
storeCossRebuildFromSwapLog(void *data)
{
    RebuildState *rb = (RebuildState *)data;
    StoreEntry *e = NULL;
    StoreSwapLogData s;
    size_t ss = sizeof(StoreSwapLogData);
    double x;
    assert(rb != NULL);
    /* load a number of objects per invocation */

    for (int aCount = 0; aCount < rb->speed; aCount++) {
        if (fread(&s, ss, 1, rb->log) != 1) {
            debugs(47, 1, "Done reading " << rb->sd->path << " swaplog (" << rb->n_read << " entries)");
            fclose(rb->log);
            rb->log = NULL;
            storeCossRebuildComplete(rb);
            return;
        }

        rb->n_read++;

        if (s.op <= SWAP_LOG_NOP)
            continue;

        if (s.op >= SWAP_LOG_MAX)
            continue;

        debugs(47, 3, "storeCossRebuildFromSwapLog: " <<
               swap_log_op_str[(int) s.op]  << " " << storeKeyText(s.key)  <<
               " "<< std::setfill('0') << std::hex << std::uppercase <<
               std::setw(8) << s.swap_filen);

        if (s.op == SWAP_LOG_ADD) {
            (void) 0;
        } else if (s.op == SWAP_LOG_DEL) {
            /* Delete unless we already have a newer copy */

            if ((e = rb->sd->get
                     (s.key)) != NULL && s.lastref > e->lastref) {
                /*
                 * Make sure we don't unlink the file, it might be
                 * in use by a subsequent entry.  Also note that
                 * we don't have to subtract from store_swap_size
                 * because adding to store_swap_size happens in
                 * the cleanup procedure.
                 */
                e->expireNow();
                e->releaseRequest();

                if (e->swap_filen > -1) {
                    e->swap_filen = -1;
                }

                e->release();
                /* Fake an unlink here, this is a bad hack :( */
                storeCossRemove(rb->sd, e);
                rb->counts.objcount--;
                rb->counts.cancelcount++;
            }
            continue;
        } else {
            x = log(static_cast<double>(++rb->counts.bad_log_op)) / log(10.0);

            if (0.0 == x - (double)
                    (int) x)
                debugs(47, 1, "WARNING: " << rb->counts.bad_log_op << " invalid swap log entries found");

            rb->counts.invalid++;

            continue;
        }

        if ((++rb->counts.scancount & 0xFFF) == 0) {

            struct stat sb;

            if (0 == fstat(fileno(rb->log), &sb))
                storeRebuildProgress(rb->sd->index,
                                     (int) sb.st_size / ss, rb->n_read);
        }

        if (EBIT_TEST(s.flags, KEY_PRIVATE)) {
            rb->counts.badflags++;
            continue;
        }

        e = rb->sd->get
            (s.key);

        if (e) {
            /* key already exists, current entry is newer */
            /* keep old, ignore new */
            rb->counts.dupcount++;
            continue;
        }

        /* update store_swap_size */
        rb->counts.objcount++;

        e = storeCossAddDiskRestore(rb->sd, s.key,
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

    eventAdd("storeCossRebuild", storeCossRebuildFromSwapLog, rb, 0.0, 1);
}

/* Add a new object to the cache with empty memory copy and pointer to disk
 * use to rebuild store from disk. */
static StoreEntry *
storeCossAddDiskRestore(CossSwapDir * SD, const cache_key * key,
                        int file_number,
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
    debugs(47, 5, "storeCossAddDiskRestore: " << storeKeyText(key)  <<
           ", fileno="<< std::setfill('0') << std::hex << std::uppercase <<
           std::setw(8) << file_number);

    /* if you call this you'd better be sure file_number is not
     * already in use! */
    e = new StoreEntry();
    e->store_status = STORE_OK;
    e->swap_dirn = SD->index;
    e->setMemStatus(NOT_IN_MEMORY);
    e->swap_status = SWAPOUT_DONE;
    e->swap_filen = file_number;
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
    e->hashInsert(key);	/* do it after we clear KEY_PRIVATE */
    storeCossAdd(SD, e);
    assert(e->swap_filen >= 0);
    return e;
}

CBDATA_TYPE(RebuildState);
static void
storeCossDirRebuild(CossSwapDir * sd)
{
    RebuildState *rb;
    int clean = 0;
    int zero = 0;
    FILE *fp;
    CBDATA_INIT_TYPE(RebuildState);
    rb = cbdataAlloc(RebuildState);
    rb->sd = sd;
    rb->speed = opt_foreground_rebuild ? 1 << 30 : 50;
    rb->flags.clean = (unsigned int) clean;
    /*
     * If the swap.state file exists in the cache_dir, then
     * we'll use storeCossRebuildFromSwapLog().
     */
    fp = storeCossDirOpenTmpSwapLog(sd, &clean, &zero);
    debugs(47, 1, "Rebuilding COSS storage in " << sd->path << " (" << (clean ? "CLEAN" : "DIRTY") << ")");
    rb->log = fp;
    StoreController::store_dirs_rebuilding++;

    if (!clean || fp == NULL) {
        /* COSS cannot yet rebuild from a dirty state. If the log
         * is dirty then the COSS contents is thrown away.
         * Why? I guess it is because some contents will be lost,
         * and COSS cannot verify this..
         */

        if (fp != NULL)
            fclose(fp);

        /*
         * XXX Make sure we don't trigger an assertion if this is the first
         * storedir, since if we are, this call will cause storeRebuildComplete
         * to prematurely complete the rebuild process, and then some other
         * storedir will try to rebuild and eventually die.
         */
        eventAdd("storeCossRebuildComplete", storeCossRebuildComplete, rb, 0.0, 0);

        return;
    }

    eventAdd("storeCossRebuild", storeCossRebuildFromSwapLog, rb, 0.0, 1);
}

static void
storeCossDirCloseTmpSwapLog(CossSwapDir * sd)
{
    char *swaplog_path = xstrdup(storeCossDirSwapLogFile(sd, NULL));
    char *new_path = xstrdup(storeCossDirSwapLogFile(sd, ".new"));
    int anfd;
    file_close(sd->swaplog_fd);

    if (xrename(new_path, swaplog_path) < 0) {
        fatal("storeCossDirCloseTmpSwapLog: rename failed");
    }

    anfd = file_open(swaplog_path, O_WRONLY | O_CREAT | O_BINARY);

    if (anfd < 0) {
        debugs(50, 1, "" << swaplog_path << ": " << xstrerror());
        fatal("storeCossDirCloseTmpSwapLog: Failed to open swap log.");
    }

    safe_free(swaplog_path);
    safe_free(new_path);
    sd->swaplog_fd = anfd;
    debugs(47, 3, "Cache COSS Dir #" << sd->index << " log opened on FD " << anfd);
}

static FILE *
storeCossDirOpenTmpSwapLog(CossSwapDir * sd, int *clean_flag, int *zero_flag)
{
    char *swaplog_path = xstrdup(storeCossDirSwapLogFile(sd, NULL));
    char *clean_path = xstrdup(storeCossDirSwapLogFile(sd, ".last-clean"));
    char *new_path = xstrdup(storeCossDirSwapLogFile(sd, ".new"));

    struct stat log_sb;

    struct stat clean_sb;
    FILE *fp;
    int anfd;

    if (::stat(swaplog_path, &log_sb) < 0) {
        debugs(50, 1, "Cache COSS Dir #" << sd->index << ": No log file");
        safe_free(swaplog_path);
        safe_free(clean_path);
        safe_free(new_path);
        return NULL;
    }

    *zero_flag = log_sb.st_size == 0 ? 1 : 0;
    /* close the existing write-only FD */

    if (sd->swaplog_fd >= 0)
        file_close(sd->swaplog_fd);

    /* open a write-only FD for the new log */
    anfd = file_open(new_path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY);

    if (anfd < 0) {
        debugs(50, 1, "" << new_path << ": " << xstrerror());
        fatal("storeDirOpenTmpSwapLog: Failed to open swap log.");
    }

    sd->swaplog_fd = anfd;
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

class CossCleanLog : public SwapDir::CleanLog
{

public:
    CossCleanLog(CossSwapDir *);
    virtual const StoreEntry *nextEntry();
    virtual void write(StoreEntry const &);
    char *cur;
    char *newLog;
    char *cln;
    char *outbuf;
    off_t outbuf_offset;
    int fd;
    dlink_node *current;
    CossSwapDir *sd;
};

#define CLEAN_BUF_SZ 16384

CossCleanLog::CossCleanLog(CossSwapDir *aSwapDir) : cur(NULL),newLog(NULL),cln(NULL),outbuf(NULL),
        outbuf_offset(0), fd(-1),current(NULL), sd(aSwapDir)
{}

/*
 * Begin the process to write clean cache state.  For COSS this means
 * opening some log files and allocating write buffers.  Return 0 if
 * we succeed, and assign the 'func' and 'data' return pointers.
 */
int
CossSwapDir::writeCleanStart()
{
    CossCleanLog *state = new CossCleanLog(this);
#if HAVE_FCHMOD

    struct stat sb;
#endif

    state->newLog = xstrdup(storeCossDirSwapLogFile(this, ".clean"));
    state->fd = file_open(state->newLog, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY);
    cleanLog = NULL;

    if (state->fd < 0) {
        xfree(state->newLog);
        delete state;
        return -1;
    }

    state->cur = xstrdup(storeCossDirSwapLogFile(this, NULL));
    state->cln = xstrdup(storeCossDirSwapLogFile(this, ".last-clean"));
    state->outbuf = (char *)xcalloc(CLEAN_BUF_SZ, 1);
    state->outbuf_offset = 0;
    ::unlink(state->cln);
    state->current = cossindex.tail;
    debugs(50, 3, "storeCOssDirWriteCleanLogs: opened " << state->newLog << ", FD " << state->fd);
#if HAVE_FCHMOD

    if (::stat(state->cur, &sb) == 0)
        fchmod(state->fd, sb.st_mode);

#endif

    cleanLog = state;

    return 0;
}

/* RBC 20050101 - I think there is a race condition here,
 * *current can be freed as its not ref counted, if/when
 * the store overruns the log writer
 */
const StoreEntry *
CossCleanLog::nextEntry()
{
    const StoreEntry *entry;

    if (!current)
        return NULL;

    entry = (const StoreEntry *) current->data;

    current = current->prev;

    return entry;
}

/*
 * "write" an entry to the clean log file.
 */
void
CossCleanLog::write(StoreEntry const &e)
{
    CossCleanLog *state = this;
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

    if (outbuf_offset + ss > CLEAN_BUF_SZ) {
        if (FD_WRITE_METHOD(fd, outbuf, outbuf_offset) < 0) {
            debugs(50, 0, "storeCossDirWriteCleanLogs: " << newLog << ": write: " << xstrerror());
            debugs(50, 0, "storeCossDirWriteCleanLogs: Current swap logfile not replaced.");
            file_close(fd);
            fd = -1;
            unlink(newLog);
            sd->cleanLog = NULL;
            delete state;
            return;
        }

        outbuf_offset = 0;
    }
}

void
CossSwapDir::writeCleanDone()
{
    CossCleanLog *state = (CossCleanLog *)cleanLog;

    if (NULL == state)
        return;

    if (state->fd < 0)
        return;

    if (FD_WRITE_METHOD(state->fd, state->outbuf, state->outbuf_offset) < 0) {
        debugs(50, 0, "storeCossDirWriteCleanLogs: " << state->newLog << ": write: " << xstrerror());
        debugs(50, 0, "storeCossDirWriteCleanLogs: Current swap logfile not replaced.");
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
    int anfd = state->fd;
    /* rename */

    if (state->fd >= 0) {
#if defined(_SQUID_OS2_) || defined(_SQUID_WIN32_)
        file_close(state->fd);
        state->fd = -1;

#endif

        xrename(state->newLog, state->cur);
    }

    /* touch a timestamp file if we're not still validating */
    if (StoreController::store_dirs_rebuilding)
        (void) 0;
    else if (anfd < 0)
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
CossSwapDir::logEntry(const StoreEntry & e, int op) const
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
               &FreeObject);
}

void
CossSwapDir::create()
{
    debugs (47, 3, "Creating swap space in " << path);

    struct stat swap_sb;
    int swap;

    if (::stat(path, &swap_sb) < 0) {
        debugs (47, 2, "COSS swap space space being allocated.");
#ifdef _SQUID_MSWIN_

        mkdir(path);
#else

        mkdir(path, 0700);
#endif

    }

    /* should check here for directories instead of files, and for file size
     * TODO - if nothing changes, there is nothing to do
     */
    swap = open(stripePath(), O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0600);

    /* TODO just set the file size */
    /* swap size is in K */
    char *block[1024];

    memset(&block, '\0', 1024);

    for (off_t offset = 0; offset < max_size; ++offset) {
        if (write (swap, block, 1024) < 1024) {
            debugs (47, 0, "Failed to create COSS swap space in " << path);
        }
    }

    close (swap);

}

/* we are shutting down, flush all membufs to disk */
CossSwapDir::~CossSwapDir()
{
    io->sync();

    if (theFile != NULL)
        theFile->close();

    delete io;

    closeLog();

    n_coss_dirs--;

    safe_free(ioModule);

    safe_free(stripe_path);
}

/*
 * storeCossDirCheckObj
 *
 * This routine is called by storeDirSelectSwapDir to see if the given
 * object is able to be stored on this filesystem. COSS filesystems will
 * not store everything. We don't check for maxobjsize here since its
 * done by the upper layers.
 */
int
CossSwapDir::canStore(StoreEntry const &e)const
{

    /* Check if the object is a special object, we can't cache these */

    if (EBIT_TEST(e.flags, ENTRY_SPECIAL))
        return -1;

    /* Otherwise, we're ok */
    /* Return load, cs->aq.aq_numpending out of MAX_ASYNCOP */
    return io->load();
}

/*
 * storeCossDirCallback - do the IO completions
 */
int
CossSwapDir::callback()
{
    return io->callback();
}

/* ========== LOCAL FUNCTIONS ABOVE, GLOBAL FUNCTIONS BELOW ========== */

void
CossSwapDir::statfs(StoreEntry & sentry) const
{
    storeAppendPrintf(&sentry, "\n");
    storeAppendPrintf(&sentry, "Maximum Size: %"PRIu64" KB\n", max_size);
    storeAppendPrintf(&sentry, "Current Size: %"PRIu64" KB\n", cur_size);
    storeAppendPrintf(&sentry, "Percent Used: %0.2f%%\n",
                      (100.0 * (double)cur_size / (double)max_size) );
    storeAppendPrintf(&sentry, "Number of object collisions: %d\n", (int) numcollisions);
#if 0
    /* is this applicable? I Hope not .. */
    storeAppendPrintf(sentry, "Filemap bits in use: %d of %d (%d%%)\n",
                      SD->map->n_files_in_map, SD->map->max_n_files,
                      Math::intPercent(SD->map->n_files_in_map, SD->map->max_n_files));
#endif

    //    storeAppendPrintf(&sentry, "Pending operations: %d out of %d\n", io->aq.aq_numpending, MAX_ASYNCOP);
    storeAppendPrintf(&sentry, "Flags:");

    if (flags.selected)
        storeAppendPrintf(&sentry, " SELECTED");

    if (flags.read_only)
        storeAppendPrintf(&sentry, " READ-ONLY");

    storeAppendPrintf(&sentry, "\n");
}

void
CossSwapDir::parse(int anIndex, char *aPath)
{
    unsigned int i;
    unsigned int size;
    off_t max_offset;

    i = GetInteger();
    size = i << 10;		/* Mbytes to Kbytes */

    if (size <= 0)
        fatal("storeCossDirParse: invalid size value");

    index = anIndex;

    path = xstrdup(aPath);

    max_size = size;

    parseOptions(0);

    if (NULL == io)
        changeIO(DiskIOModule::FindDefault());

    /* Enforce maxobjsize being set to something */
    if (max_objsize == -1)
        fatal("COSS requires max-size to be set to something other than -1!\n");

    if (max_objsize > COSS_MEMBUF_SZ)
        fatalf("COSS max-size option must be less than COSS_MEMBUF_SZ (%d)\n",
               COSS_MEMBUF_SZ);

    /*
     * check that we won't overflow sfileno later.  0xFFFFFF is the
     * largest possible sfileno, assuming sfileno is a 25-bit
     * signed integer, as defined in structs.h.
     */
    max_offset = (off_t) 0xFFFFFF << blksz_bits;

    if ((off_t)max_size > (max_offset>>10)) {
        debugs(47, 0, "COSS block-size = " << (1<<blksz_bits) << " bytes");
        debugs(47,0, "COSS largest file offset = " << (max_offset >> 10) << " KB");
        debugs(47, 0, "COSS cache_dir size = " << max_size << " KB");
        fatal("COSS cache_dir size exceeds largest offset\n");
    }
}


void
CossSwapDir::reconfigure(int index, char *path)
{
    unsigned int i;
    unsigned int size;

    i = GetInteger();
    size = i << 10;		/* Mbytes to Kbytes */

    if (size <= 0)
        fatal("storeCossDirParse: invalid size value");

    if (size == (size_t)max_size)
        debugs(3, 1, "Cache COSS dir '" << path << "' size remains unchanged at " << size << " KB");
    else {
        debugs(3, 1, "Cache COSS dir '" << path << "' size changed to " << size << " KB");
        max_size = size;
    }

    /* Enforce maxobjsize being set to something */
    if (max_objsize == -1)
        fatal("COSS requires max-size to be set to something other than -1!\n");
}

void
CossSwapDir::dump(StoreEntry &entry)const
{
    storeAppendPrintf(&entry, " %"PRIu64"", (max_size >> 10));
    dumpOptions(&entry);
}

CossSwapDir::CossSwapDir() : SwapDir ("coss"), swaplog_fd(-1), count(0), current_membuf (NULL), current_offset(0), numcollisions(0),  blksz_bits(0), io (NULL), ioModule(NULL), currentIOOptions(new ConfigOptionVector()), stripe_path(NULL)
{
    membufs.head = NULL;
    membufs.tail = NULL;
    cossindex.head = NULL;
    cossindex.tail = NULL;
    blksz_mask = (1 << blksz_bits) - 1;
    repl = NULL;
}

bool
CossSwapDir::optionBlockSizeParse(const char *option, const char *value, int reconfiguring)
{
    assert(option);

    if (strcmp(option, "block-size") != 0)
        return false;

    if (!value)
        self_destruct();

    int blksz = atoi(value);

    if (blksz == (1 << blksz_bits))
        /* no change */
        return true;

    if (reconfiguring) {
        debugs(47, 0, "WARNING: cannot change COSS block-size while Squid is running");
        return false;
    }

    int nbits = 0;
    int check = blksz;

    while (check > 1) {
        nbits++;
        check >>= 1;
    }

    check = 1 << nbits;

    if (check != blksz)
        fatal("COSS block-size must be a power of 2\n");

    if (nbits > 13)
        fatal("COSS block-size must be 8192 or smaller\n");

    blksz_bits = nbits;

    blksz_mask = (1 << blksz_bits) - 1;

    return true;
}

void
CossSwapDir::optionBlockSizeDump(StoreEntry * e) const
{
    storeAppendPrintf(e, " block-size=%d", 1 << blksz_bits);
}

StoreSearch *
CossSwapDir::search(String const url, HttpRequest *)
{
    if (url.size())
        fatal ("Cannot search by url yet\n");

    return new StoreSearchCoss (this);
}

char const *
CossSwapDir::stripePath() const
{
    if (!stripe_path) {
        String result = path;
        result.append("/stripe");
        const_cast<CossSwapDir *>(this)->stripe_path = xstrdup(result.termedBuf());
    }

    return stripe_path;
}

CBDATA_CLASS_INIT(StoreSearchCoss);
StoreSearchCoss::StoreSearchCoss(RefCount<CossSwapDir> aSwapDir) : sd(aSwapDir), callback (NULL), cbdata(NULL),  _done (false), current(NULL), next_(sd->cossindex.tail)
{
    /* TODO: this races with the store as does the cleanlog stuff.
     * FIXME by making coss_nodes ref counted */
}

/* do not link
StoreSearchCoss::StoreSearchCoss(StoreSearchCoss const &);
*/

StoreSearchCoss::~StoreSearchCoss()
{}

void
StoreSearchCoss::next(void (callback)(void *cbdata), void *cbdata)
{
    next();
    callback (cbdata);
}

bool
StoreSearchCoss::next()
{
    current = next_;

    if (next_)
        next_ = next_->prev;

    if (!current)
        _done = true;

    return current != NULL;
}

bool
StoreSearchCoss::error() const
{
    return false;
}

bool
StoreSearchCoss::isDone() const
{
    return _done;
}

StoreEntry *
StoreSearchCoss::currentItem()
{
    if (!current)
        return NULL;

    return static_cast<StoreEntry *>( current->data );
}
