
/*
 * $Id: store_dir_coss.cc,v 1.45 2003/07/15 11:33:23 robertc Exp $
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
#include "Store.h"
#include <aio.h>

#include "async_io.h"
#include "store_coss.h"
#include "fde.h"
#include "SwapDir.h"
#include "StoreSwapLogData.h"

#define STORE_META_BUFSZ 4096

int n_coss_dirs = 0;
/* static int last_coss_pick_index = -1; */
int coss_initialised = 0;
MemPool *coss_index_pool = NULL;

typedef struct _RebuildState RebuildState;

struct _RebuildState
{
    CossSwapDir *sd;
    int n_read;
    FILE *log;
    int speed;

    struct
    {

unsigned int clean:
        1;
    }

    flags;

    struct _store_rebuild_data counts;
};

static char *storeCossDirSwapLogFile(SwapDir *, const char *);
static EVH storeCossRebuildFromSwapLog;
static StoreEntry *storeCossAddDiskRestore(CossSwapDir * SD, const cache_key * key,
        int file_number,
        size_t swap_file_sz,
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

/* The "only" externally visible function */
STSETUP storeFsSetup_coss;

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

        for (pathtmp2 = pathtmp; *pathtmp2 == '.'; pathtmp2++)

            ;
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
        debug(47, 1) ("%s: %s\n", logPath, xstrerror());
        fatal("storeCossDirOpenSwapLog: Failed to open swap log.");
    }

    debug(47, 3) ("Cache COSS Dir #%d log opened on FD %d\n", index, swaplog_fd);
}

void
CossSwapDir::closeLog()
{
    if (swaplog_fd < 0)	/* not open */
        return;

    file_close(swaplog_fd);

    debug(47, 3) ("Cache COSS Dir #%d log closed on FD %d\n",
                  index, swaplog_fd);

    swaplog_fd = -1;
}

void
CossSwapDir::init()
{
    a_file_setupqueue(&aq);
    openLog();
    storeCossDirRebuild(this);
    fd = file_open(path, O_RDWR | O_CREAT);

    if (fd < 0) {
        debug(47, 1) ("%s: %s\n", path, xstrerror());
        fatal("storeCossDirInit: Failed to open a COSS directory.");
    }

    n_coss_dirs++;
    (void) storeDirGetBlkSize(path, &fs.blksize);
}

void
storeCossRemove(CossSwapDir * sd, StoreEntry * e)
{
    CossIndexNode *coss_node = (CossIndexNode *)e->repl.data;
    e->repl.data = NULL;
    dlinkDelete(&coss_node->node, &sd->cossindex);
    memPoolFree(coss_index_pool, coss_node);
    sd->count -= 1;
}

void
storeCossAdd(CossSwapDir * sd, StoreEntry * e)
{
    CossIndexNode *coss_node = (CossIndexNode *)memPoolAlloc(coss_index_pool);
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
    storeCossStartMembuf(sd);
    store_dirs_rebuilding--;
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
            debug(47, 1) ("Done reading %s swaplog (%d entries)\n",
                          rb->sd->path, rb->n_read);
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

        debug(47, 3) ("storeCossRebuildFromSwapLog: %s %s %08X\n",
                      swap_log_op_str[(int) s.op],
                      storeKeyText(s.key),
                      s.swap_filen);

        if (s.op == SWAP_LOG_ADD) {
            (void) 0;
        } else if (s.op == SWAP_LOG_DEL) {
            /* Delete unless we already have a newer copy */

            if ((e = storeGet(s.key)) != NULL && s.lastref > e->lastref) {
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
                    e->swap_filen = -1;
                }

                storeRelease(e);
                /* Fake an unlink here, this is a bad hack :( */
                storeCossRemove(rb->sd, e);
                rb->counts.objcount--;
                rb->counts.cancelcount++;
            }

            continue;
        } else {
            x = log(++rb->counts.bad_log_op) / log(10.0);

            if (0.0 == x - (double) (int) x)
                debug(47, 1) ("WARNING: %d invalid swap log entries found\n",
                              rb->counts.bad_log_op);

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

        e = storeGet(s.key);

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
    debug(47, 5) ("storeCossAddDiskRestore: %s, fileno=%08X\n", storeKeyText(key), file_number);
    /* if you call this you'd better be sure file_number is not
     * already in use! */
    e = new_StoreEntry(STORE_ENTRY_WITHOUT_MEMOBJ, NULL, NULL);
    e->store_status = STORE_OK;
    e->swap_dirn = SD->index;
    storeSetMemStatus(e, NOT_IN_MEMORY);
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
    storeHashInsert(e, key);	/* do it after we clear KEY_PRIVATE */
    storeCossAdd(SD, e);
    e->swap_filen = storeCossAllocate(SD, e, COSS_ALLOC_NOTIFY);
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
    EVH *func = NULL;
    CBDATA_INIT_TYPE(RebuildState);
    rb = cbdataAlloc(RebuildState);
    rb->sd = sd;
    rb->speed = opt_foreground_rebuild ? 1 << 30 : 50;
    func = storeCossRebuildFromSwapLog;
    rb->flags.clean = (unsigned int) clean;
    /*
     * If the swap.state file exists in the cache_dir, then
     * we'll use storeCossRebuildFromSwapLog().
     */
    fp = storeCossDirOpenTmpSwapLog(sd, &clean, &zero);
    debug(47, 1) ("Rebuilding COSS storage in %s (%s)\n",
                  sd->path, clean ? "CLEAN" : "DIRTY");
    rb->log = fp;
    store_dirs_rebuilding++;

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

    eventAdd("storeCossRebuild", func, rb, 0.0, 1);
}

static void
storeCossDirCloseTmpSwapLog(CossSwapDir * sd)
{
    char *swaplog_path = xstrdup(storeCossDirSwapLogFile(sd, NULL));
    char *new_path = xstrdup(storeCossDirSwapLogFile(sd, ".new"));
    int anfd;
    file_close(sd->swaplog_fd);
#if defined (_SQUID_OS2_) || defined (_SQUID_CYGWIN_)

    if (unlink(swaplog_path) < 0) {
        debug(50, 0) ("%s: %s\n", swaplog_path, xstrerror());
        fatal("storeCossDirCloseTmpSwapLog: unlink failed");
    }

#endif
    if (xrename(new_path, swaplog_path) < 0) {
        fatal("storeCossDirCloseTmpSwapLog: rename failed");
    }

    anfd = file_open(swaplog_path, O_WRONLY | O_CREAT | O_BINARY);

    if (anfd < 0) {
        debug(50, 1) ("%s: %s\n", swaplog_path, xstrerror());
        fatal("storeCossDirCloseTmpSwapLog: Failed to open swap log.");
    }

    safe_free(swaplog_path);
    safe_free(new_path);
    sd->swaplog_fd = anfd;
    debug(47, 3) ("Cache COSS Dir #%d log opened on FD %d\n", sd->index, anfd);
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

    if (stat(swaplog_path, &log_sb) < 0) {
        debug(50, 1) ("Cache COSS Dir #%d: No log file\n", sd->index);
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
        debug(50, 1) ("%s: %s\n", new_path, xstrerror());
        fatal("storeDirOpenTmpSwapLog: Failed to open swap log.");
    }

    sd->swaplog_fd = anfd;
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

class CossCleanLog : public SwapDir::CleanLog
{

public:
    CossCleanLog(SwapDir *);
    virtual const StoreEntry *nextEntry();
    virtual void write(StoreEntry const &);
    char *cur;
    char *newLog;
    char *cln;
    char *outbuf;
    off_t outbuf_offset;
    int fd;
    dlink_node *current;
    SwapDir *sd;
};

#define CLEAN_BUF_SZ 16384

CossCleanLog::CossCleanLog(SwapDir *aSwapDir) : cur(NULL),newLog(NULL),cln(NULL),outbuf(NULL),
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
    debug(50, 3) ("storeCOssDirWriteCleanLogs: opened %s, FD %d\n",
                  state->newLog, state->fd);
#if HAVE_FCHMOD

    if (stat(state->cur, &sb) == 0)
        fchmod(state->fd, sb.st_mode);

#endif

    cleanLog = state;

    return 0;
}

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
    xmemcpy(&s.key, e.key, MD5_DIGEST_CHARS);
    xmemcpy(state->outbuf + state->outbuf_offset, &s, ss);
    state->outbuf_offset += ss;
    /* buffered write */

    if (state->outbuf_offset + ss > CLEAN_BUF_SZ) {
        if (FD_WRITE_METHOD(state->fd, state->outbuf, state->outbuf_offset) < 0) {
            debug(50, 0) ("storeCossDirWriteCleanLogs: %s: write: %s\n",
                          state->newLog, xstrerror());
            debug(50, 0) ("storeCossDirWriteCleanLogs: Current swap logfile not replaced.\n");
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
CossSwapDir::writeCleanDone()
{
    CossCleanLog *state = (CossCleanLog *)cleanLog;

    if (NULL == state)
        return;

    if (state->fd < 0)
        return;

    if (FD_WRITE_METHOD(state->fd, state->outbuf, state->outbuf_offset) < 0) {
        debug(50, 0) ("storeCossDirWriteCleanLogs: %s: write: %s\n",
                      state->newLog, xstrerror());
        debug(50, 0) ("storeCossDirWriteCleanLogs: Current swap logfile "
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
    int anfd = state->fd;
    /* rename */

    if (state->fd >= 0) {
#if defined(_SQUID_OS2_) || defined (_SQUID_CYGWIN_)
        file_close(state->fd);
        state->fd = -1;

        if (unlink(state->cur) < 0)
            debug(50, 0) ("storeCossDirWriteCleanLogs: unlinkd failed: %s, %s\n",
                          xstrerror(), state->cur);

#endif

        xrename(state->newLog, state->cur);
    }

    /* touch a timestamp file if we're not still validating */
    if (store_dirs_rebuilding)
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
    xmemcpy(s->key, e.key, MD5_DIGEST_CHARS);
    file_write(swaplog_fd,
               -1,
               s,
               sizeof(StoreSwapLogData),
               NULL,
               NULL,
               &FreeObject<StoreSwapLogData>);
}

void
CossSwapDir::newFileSystem()
{
    debug(47, 3) ("Creating swap space in %s\n", path);
    debug (47,0)("COSS autocreation is not implemented. Please create the file manually\n");
}

/* we are shutting down, flush all membufs to disk */
CossSwapDir::~CossSwapDir()
{
    sync();				/* This'll call a_file_syncqueue() */
    a_file_closequeue(&aq);
    file_close(fd);
    fd = -1;

    closeLog();
    n_coss_dirs--;
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
    int loadav;

    /* Check if the object is a special object, we can't cache these */

    if (EBIT_TEST(e.flags, ENTRY_SPECIAL))
        return -1;

    /* Otherwise, we're ok */
    /* Return load, cs->aq.aq_numpending out of MAX_ASYNCOP */
    loadav = aq.aq_numpending * 1000 / MAX_ASYNCOP;

    return loadav;
}

/*
 * storeCossDirCallback - do the IO completions
 */
int
CossSwapDir::callback()
{
    return a_file_callback(&aq);
}

/* ========== LOCAL FUNCTIONS ABOVE, GLOBAL FUNCTIONS BELOW ========== */

void
CossSwapDir::statfs(StoreEntry & sentry) const
{
    storeAppendPrintf(&sentry, "\n");
    storeAppendPrintf(&sentry, "Maximum Size: %d KB\n", max_size);
    storeAppendPrintf(&sentry, "Current Size: %d KB\n", cur_size);
    storeAppendPrintf(&sentry, "Percent Used: %0.2f%%\n",
                      100.0 * cur_size / max_size);
    storeAppendPrintf(&sentry, "Number of object collisions: %d\n", (int) numcollisions);
#if 0
    /* is this applicable? I Hope not .. */
    storeAppendPrintf(sentry, "Filemap bits in use: %d of %d (%d%%)\n",
                      SD->map->n_files_in_map, SD->map->max_n_files,
                      percent(SD->map->n_files_in_map, SD->map->max_n_files));
#endif

    storeAppendPrintf(&sentry, "Pending operations: %d out of %d\n", aq.aq_numpending, MAX_ASYNCOP);
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

    i = GetInteger();
    size = i << 10;		/* Mbytes to Kbytes */

    if (size <= 0)
        fatal("storeCossDirParse: invalid size value");

    index = anIndex;

    path = xstrdup(aPath);

    max_size = size;

    parse_cachedir_options(this, NULL, 0);

    /* Enforce maxobjsize being set to something */
    if (max_objsize == -1)
        fatal("COSS requires max-size to be set to something other than -1!\n");
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
        debug(3, 1) ("Cache COSS dir '%s' size remains unchanged at %d KB\n", path, size);
    else {
        debug(3, 1) ("Cache COSS dir '%s' size changed to %d KB\n", path, size);
        max_size = size;
    }

    parse_cachedir_options(this, NULL, 1);
    /* Enforce maxobjsize being set to something */

    if (max_objsize == -1)
        fatal("COSS requires max-size to be set to something other than -1!\n");
}

void
CossSwapDir::dump(StoreEntry &entry)const
{
    storeAppendPrintf(&entry, " %d",
                      max_size >> 20);
    dump_cachedir_options(&entry, NULL, this);
}

#if OLD_UNUSED_CODE
SwapDir *
storeCossDirPick(void)
{
    int i, choosenext = 0;
    SwapDir *SD;

    if (n_coss_dirs == 0)
        return NULL;

    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
        SD = &Config.cacheSwap.swapDirs[i];

        if (SD->type == SWAPDIR_COSS) {
            if ((last_coss_pick_index == -1) || (n_coss_dirs == 1)) {
                last_coss_pick_index = i;
                return SD;
            } else if (choosenext) {
                last_coss_pick_index = i;
                return SD;
            } else if (last_coss_pick_index == i) {
                choosenext = 1;
            }
        }
    }

    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
        SD = &Config.cacheSwap.swapDirs[i];

        if (SD->type == SWAPDIR_COSS) {
            if ((last_coss_pick_index == -1) || (n_coss_dirs == 1)) {
                last_coss_pick_index = i;
                return SD;
            } else if (choosenext) {
                last_coss_pick_index = i;
                return SD;
            } else if (last_coss_pick_index == i) {
                choosenext = 1;
            }
        }
    }

    return NULL;
}

#endif

/*
 * initial setup/done code
 */
static void
storeCossDirDone(void)
{
    /*  memPoolDestroy(&coss_index_pool);  XXX Should be here? */
    coss_initialised = 0;
}

static SwapDir *
storeCossNew(void)
{
    SwapDir *result = new CossSwapDir;
    return result;
}

CossSwapDir::CossSwapDir() : fd (-1), swaplog_fd(-1), count(0), current_membuf (NULL), current_offset(0), numcollisions(0)
{
    membufs.head = NULL;
    membufs.tail = NULL;
    cossindex.head = NULL;
    cossindex.tail = NULL;
}

void
storeFsSetup_coss(storefs_entry_t * storefs)
{
    assert(!coss_initialised);

    storefs->donefunc = storeCossDirDone;
    storefs->newfunc = storeCossNew;
    coss_index_pool = memPoolCreate("COSS index data", sizeof(CossIndexNode));
    coss_initialised = 1;
}
