#include "squid.h"

#define STORE_META_BUFSZ 4096


typedef struct _rebuild_dir rebuild_dir;
typedef RBHD(rebuild_dir * d);

struct _rebuild_dir {
    int dirn;
    int n_read;
    FILE *log;
    int speed;
    int clean;
    int curlvl1;
    int curlvl2;
    int flag;
    int done;
    int in_dir;
    int fn;
    struct dirent *entry;
    DIR *td;
    RBHD *rebuild_func;
    rebuild_dir *next;
};

struct storeRebuildState {
    rebuild_dir *rebuild_dir;
    int objcount;		/* # objects successfully reloaded */
    int expcount;		/* # objects expired */
    int linecount;		/* # lines parsed from cache logfile */
    int statcount;		/* # entries from directory walking */
    int clashcount;		/* # swapfile clashes avoided */
    int dupcount;		/* # duplicates purged */
    int cancelcount;		/* # SWAP_LOG_DEL objects purged */
    int invalid;		/* # bad lines */
    int badflags;		/* # bad e->flags */
    int need_to_validate;
    int bad_log_op;
    int zero_object_len;
    time_t start;
    time_t stop;
} RebuildState;

typedef struct valid_ctrl_t {
    struct stat *sb;
    StoreEntry *e;
    STVLDCB *callback;
    void *callback_data;
} valid_ctrl_t;

static RBHD storeRebuildFromDirectory;
static RBHD storeRebuildFromSwapLog;
static void storeRebuildComplete(void);
static EVH storeRebuildADirectory;
static int storeGetNextFile(rebuild_dir *, int *sfileno, int *size);

static int
storeRebuildFromDirectory(rebuild_dir * d)
{
    LOCAL_ARRAY(char, hdr_buf, DISK_PAGE_SIZE);
    StoreEntry *e = NULL;
    StoreEntry tmpe;
    cache_key key[MD5_DIGEST_CHARS];
    int sfileno = 0;
    int count;
    int size;
    struct stat fst;
    int hdr_len;
    int fd = -1;
    tlv *tlv_list;
    tlv *t;
    double x;
    assert(d != NULL);
    debug(20, 3) ("storeRebuildFromDirectory: DIR #%d\n", d->dirn);
    for (count = 0; count < d->speed; count++) {
	assert(fd == -1);
	fd = storeGetNextFile(d, &sfileno, &size);
	if (fd == -2) {
	    debug(20, 1) ("storeRebuildFromDirectory: DIR #%d done!\n", d->dirn);
	    storeDirCloseTmpSwapLog(d->dirn);
	    store_rebuilding = 0;
	    return -1;
	} else if (fd < 0) {
	    continue;
	}
	assert(fd > -1);
	/* lets get file stats here */
	if (fstat(fd, &fst) < 0) {
	    debug(20, 1) ("storeRebuildFromDirectory: fstat(FD %d): %s\n",
		fd, xstrerror());
	    file_close(fd);
	    fd = -1;
	    continue;
	}
	if ((++RebuildState.statcount & 0x3FFF) == 0)
	    debug(20, 1) ("  %7d files opened so far.\n",
		RebuildState.statcount);
	debug(20, 9) ("file_in: fd=%d %08x\n", fd, sfileno);
	if (read(fd, hdr_buf, DISK_PAGE_SIZE) < 0) {
	    debug(20, 1) ("storeRebuildFromDirectory: read(FD %d): %s\n",
		fd, xstrerror());
	    file_close(fd);
	    fd = -1;
	    continue;
	}
	file_close(fd);
	fd = -1;
	hdr_len = 0;
	tlv_list = storeSwapMetaUnpack(hdr_buf, &hdr_len);
	if (tlv_list == NULL) {
	    debug(20, 1) ("storeRebuildFromDirectory: failed to get meta data\n");
	    storeUnlinkFileno(sfileno);
	    continue;
	}
	debug(20, 3) ("storeRebuildFromDirectory: successful swap meta unpacking\n");
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
	    debug(20, 1) ("storeRebuildFromDirectory: NULL key\n");
	    storeUnlinkFileno(sfileno);
	    continue;
	}
	tmpe.key = key;
	if (tmpe.object_len == 0) {
	    RebuildState.invalid++;
	    x = log(++RebuildState.zero_object_len) / log(10.0);
	    if (0.0 == x - (double) (int) x)
		debug(20, 1) ("WARNING: %d swapfiles found with ZERO length\n",
		    RebuildState.zero_object_len);
	    storeUnlinkFileno(sfileno);
	    continue;
	}
	/* check sizes */
	if (hdr_len + tmpe.object_len != fst.st_size) {
	    debug(20, 1) ("storeRebuildFromDirectory: SIZE MISMATCH %d+%d!=%d\n",
		hdr_len, tmpe.object_len, fst.st_size);
	    storeUnlinkFileno(sfileno);
	    continue;
	}
	if (EBIT_TEST(tmpe.flag, KEY_PRIVATE)) {
	    storeUnlinkFileno(sfileno);
	    RebuildState.badflags++;
	    continue;
	}
	if ((e = storeGet(key)) != NULL) {
	    /* URL already exists, this swapfile not being used */
	    /* junk old, load new */
	    storeRelease(e);	/* release old entry */
	    RebuildState.dupcount++;
	}
	RebuildState.objcount++;
	storeEntryDump(&tmpe, 5);
	e = storeAddDiskRestore(key,
	    sfileno,
	    (int) tmpe.object_len,
	    tmpe.expires,
	    tmpe.timestamp,
	    tmpe.lastref,
	    tmpe.lastmod,
	    tmpe.refcount,	/* refcount */
	    tmpe.flag,		/* flags */
	    d->clean);
    }
    return count;
}

static int
storeRebuildFromSwapLog(rebuild_dir * d)
{
    StoreEntry *e = NULL;
    storeSwapData s;
    size_t ss = sizeof(storeSwapData);
    int count;
    int used;			/* is swapfile already in use? */
    int newer;			/* is the log entry newer than current entry? */
    double x;
    assert(d != NULL);
    /* load a number of objects per invocation */
    for (count = 0; count < d->speed; count++) {
	if (fread(&s, ss, 1, d->log) != 1) {
	    debug(20, 1) ("Done reading Cache Dir #%d swaplog (%d entries)\n",
		d->dirn, d->n_read);
	    fclose(d->log);
	    d->log = NULL;
	    storeDirCloseTmpSwapLog(d->dirn);
	    return -1;
	}
	d->n_read++;
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
		storeSetPrivateKey(e);
		EBIT_SET(e->flag, RELEASE_REQUEST);
		if (e->swap_file_number > -1) {
		    storeDirMapBitReset(e->swap_file_number);
		    e->swap_file_number = -1;
		}
		RebuildState.objcount--;
		RebuildState.cancelcount++;
	    }
	    continue;
	} else {
	    x = log(++RebuildState.bad_log_op) / log(10.0);
	    if (0.0 == x - (double) (int) x)
		debug(20, 1) ("WARNING: %d invalid swap log entries found\n",
		    RebuildState.bad_log_op);
	    RebuildState.invalid++;
	    continue;
	}
	if ((++RebuildState.linecount & 0x3FFF) == 0)
	    debug(20, 1) ("  %7d Entries read so far.\n",
		RebuildState.linecount);
	if (!storeDirValidFileno(s.swap_file_number)) {
	    RebuildState.invalid++;
	    continue;
	}
	if (EBIT_TEST(s.flags, KEY_PRIVATE)) {
	    RebuildState.badflags++;
	    continue;
	}
	e = storeGet(s.key);
	used = storeDirMapBitTest(s.swap_file_number);
	/* If this URL already exists in the cache, does the swap log
	 * appear to have a newer entry?  Compare 'lastref' from the
	 * swap log to e->lastref. */
	newer = e ? (s.lastref > e->lastref ? 1 : 0) : 0;
	if (used && !newer) {
	    /* log entry is old, ignore it */
	    RebuildState.clashcount++;
	    continue;
	} else if (used && e && e->swap_file_number == s.swap_file_number) {
	    /* swapfile taken, same URL, newer, update meta */
	    e->lastref = s.timestamp;
	    e->timestamp = s.timestamp;
	    e->expires = s.expires;
	    e->lastmod = s.lastmod;
	    e->flag |= s.flags;
	    e->refcount += s.refcount;
	    continue;
	} else if (used) {
	    /* swapfile in use, not by this URL, log entry is newer */
	    /* This is sorta bad: the log entry should NOT be newer at this
	     * point.  If the log is dirty, the filesize check should have
	     * caught this.  If the log is clean, there should never be a
	     * newer entry. */
	    debug(20, 1) ("WARNING: newer swaplog entry for fileno %08X\n",
		s.swap_file_number);
	    /* I'm tempted to remove the swapfile here just to be safe,
	     * but there is a bad race condition in the NOVM version if
	     * the swapfile has recently been opened for writing, but
	     * not yet opened for reading.  Because we can't map
	     * swapfiles back to StoreEntrys, we don't know the state
	     * of the entry using that file.  */
	    /* We'll assume the existing entry is valid, probably because
	     * were in a slow rebuild and the the swap file number got taken
	     * and the validation procedure hasn't run. */
	    assert(RebuildState.need_to_validate);
	    RebuildState.clashcount++;
	    continue;
	} else if (e) {
	    /* URL already exists, this swapfile not being used */
	    /* junk old, load new */
	    storeRelease(e);	/* release old entry */
	    RebuildState.dupcount++;
	} else {
	    /* URL doesnt exist, swapfile not in use */
	    /* load new */
	    (void) 0;
	}
	/* update store_swap_size */
	RebuildState.objcount++;
	e = storeAddDiskRestore(s.key,
	    s.swap_file_number,
	    s.object_len,
	    s.expires,
	    s.timestamp,
	    s.lastref,
	    s.lastmod,
	    s.refcount,
	    s.flags,
	    d->clean);
	storeDirSwapLog(e, SWAP_LOG_ADD);
    }
    return count;
}

static void
storeRebuildADirectory(void *unused)
{
    int count;
    rebuild_dir *d;
    rebuild_dir **D;
    if ((d = RebuildState.rebuild_dir) == NULL) {
	storeRebuildComplete();
	return;
    }
    count = d->rebuild_func(d);
    RebuildState.rebuild_dir = d->next;
    if (count < 0) {
	xfree(d);
    } else {
	for (D = &RebuildState.rebuild_dir; *D; D = &(*D)->next);
	*D = d;
	d->next = NULL;
    }
    if (opt_foreground_rebuild)
	storeRebuildADirectory(NULL);
    else
	eventAdd("storeRebuild", storeRebuildADirectory, NULL, 0);
}

void
storeConvertFile(const cache_key * key,
    int file_number,
    int size,
    time_t expires,
    time_t timestamp,
    time_t lastref,
    time_t lastmod,
    u_short refcount,
    u_short flags,
    int clean)
{
    int fd_r, fd_w;
    int hdr_len, x, y;
    LOCAL_ARRAY(char, swapfilename, SQUID_MAXPATHLEN);
    LOCAL_ARRAY(char, copybuf, DISK_PAGE_SIZE);
    char *buf;
    tlv *tlv_list;
    StoreEntry e;
    e.key = key;
    e.object_len = size;
    e.expires = expires;
    e.lastref = lastref;
    e.refcount = refcount;
    e.flag = flags;
    storeSwapFullPath(file_number, swapfilename);
    fd_r = file_open(swapfilename, O_RDONLY, NULL, NULL, NULL);
    if (fd_r < 0)
	return;
    safeunlink(swapfilename, 1);
    fd_w = file_open(swapfilename, O_CREAT | O_WRONLY | O_TRUNC, NULL, NULL, NULL);
    tlv_list = storeSwapMetaBuild(&e);
    buf = storeSwapMetaPack(tlv_list, &hdr_len);
    x = write(fd_w, buf, hdr_len);
    while (x > 0) {
	y = read(fd_r, copybuf, DISK_PAGE_SIZE);
	x = write(fd_w, copybuf, y);
    }
    file_close(fd_r);
    file_close(fd_w);
    xfree(buf);
    storeSwapTLVFree(tlv_list);
}

static int
storeGetNextFile(rebuild_dir * d, int *sfileno, int *size)
{
    int fd = -1;
    int used = 0;
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    LOCAL_ARRAY(char, fullpath, SQUID_MAXPATHLEN);
    debug(20, 3) ("storeGetNextFile: flag=%d, %d: /%02X/%02X\n",
	d->flag,
	d->dirn,
	d->curlvl1,
	d->curlvl2);
    if (d->done)
	return -2;
    while (fd < 0 && d->done == 0) {
	fd = -1;
	if (!d->flag) {		/* initialize, open first file */
	    d->done = d->dirn = d->curlvl1 = d->curlvl2 = d->in_dir = 0;
	    d->flag = 1;
	    assert(Config.cacheSwap.n_configured > 0);
	}
	if (!d->in_dir) {	/* we need to read in a new directory */
	    snprintf(fullpath, SQUID_MAXPATHLEN, "%s/%02X/%02X",
		Config.cacheSwap.swapDirs[d->dirn].path,
		d->curlvl1, d->curlvl2);
	    if (d->flag && d->td)
		closedir(d->td);
	    d->td = opendir(fullpath);
	    d->entry = readdir(d->td);	/* skip . and .. */
	    d->entry = readdir(d->td);
	    if (errno == ENOENT) {
		debug(20, 3) ("storeGetNextFile: directory does not exist!.\n");
	    }
	    debug(20, 3) ("storeGetNextFile: Directory %s/%02X/%02X\n",
		Config.cacheSwap.swapDirs[d->dirn].path,
		d->curlvl1, d->curlvl2);
	}
	if ((d->entry = readdir(d->td))) {
	    d->in_dir++;
	    if (sscanf(d->entry->d_name, "%x", sfileno) != 1) {
		debug(20, 3) ("storeGetNextFile: invalid %s\n",
		    d->entry->d_name);
		continue;
	    }
	    d->fn = *sfileno;
	    d->fn = storeDirProperFileno(d->dirn, d->fn);
	    *sfileno = d->fn;
	    used = storeDirMapBitTest(d->fn);
	    if (used) {
		debug(20, 3) ("storeGetNextFile: Locked, continuing with next.\n");
		continue;
	    }
	    snprintf(fullfilename, SQUID_MAXPATHLEN, "%s/%s",
		fullpath, d->entry->d_name);
	    debug(20, 3) ("storeGetNextFile: Opening %s\n", fullfilename);
	    fd = file_open(fullfilename, O_RDONLY, NULL, NULL, NULL);
	    continue;
	}
	d->in_dir = 0;
	d->curlvl2 = (d->curlvl2 + 1) % Config.cacheSwap.swapDirs[d->dirn].l2;
	if (d->curlvl2 != 0)
	    continue;
	d->curlvl1 = (d->curlvl1 + 1) % Config.cacheSwap.swapDirs[d->dirn].l1;
	if (d->curlvl1 != 0)
	    continue;
	d->dirn = (d->dirn + 1) % Config.cacheSwap.n_configured;
	if (d->dirn != 0)
	    continue;
	else
	    d->done = 1;
    }
    return fd;
}

/* Add a new object to the cache with empty memory copy and pointer to disk
 * use to rebuild store from disk. */
StoreEntry *
storeAddDiskRestore(const cache_key * key,
    int file_number,
    int size,
    time_t expires,
    time_t timestamp,
    time_t lastref,
    time_t lastmod,
    u_num32 refcount,
    u_num32 flags,
    int clean)
{
    StoreEntry *e = NULL;
    debug(20, 5) ("StoreAddDiskRestore: %s, fileno=%08X\n", storeKeyText(key), file_number);
    /* if you call this you'd better be sure file_number is not 
     * already in use! */
    e = new_StoreEntry(STORE_ENTRY_WITHOUT_MEMOBJ, NULL, NULL);
    storeHashInsert(e, key);
    e->store_status = STORE_OK;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    e->swap_status = SWAPOUT_DONE;
    e->swap_file_number = file_number;
    e->object_len = size;
    e->lock_count = 0;
    e->refcount = 0;
    e->lastref = lastref;
    e->timestamp = timestamp;
    e->expires = expires;
    e->lastmod = lastmod;
    e->refcount = refcount;
    e->flag = flags;
    EBIT_SET(e->flag, ENTRY_CACHABLE);
    EBIT_CLR(e->flag, RELEASE_REQUEST);
    EBIT_CLR(e->flag, KEY_PRIVATE);
    e->ping_status = PING_NONE;
    EBIT_CLR(e->flag, ENTRY_VALIDATED);
    storeDirMapBitSet(e->swap_file_number);
    return e;
}

void
storeCleanup(void *datanotused)
{
    static int bucketnum = -1;
    static int validnum = 0;
    StoreEntry *e;
    hash_link *link_ptr = NULL;
    if (++bucketnum >= store_hash_buckets) {
	debug(20, 1) ("  Completed Validation Procedure\n");
	debug(20, 1) ("  Validated %d Entries\n", validnum);
	debug(20, 1) ("  store_swap_size = %dk\n", store_swap_size);
	store_rebuilding = 0;
	return;
    }
    link_ptr = hash_get_bucket(store_table, bucketnum);
    for (; link_ptr; link_ptr = link_ptr->next) {
	e = (StoreEntry *) link_ptr;
	if (EBIT_TEST(e->flag, ENTRY_VALIDATED))
	    continue;
	if (e->swap_file_number < 0)
	    continue;
	EBIT_SET(e->flag, ENTRY_VALIDATED);
	/* Only set the file bit if we know its a valid entry */
	/* otherwise, set it in the validation procedure */
	storeDirUpdateSwapSize(e->swap_file_number, e->object_len, 1);
	if ((++validnum & 0xFFFF) == 0)
	    debug(20, 1) ("  %7d Entries Validated so far.\n", validnum);
	assert(validnum <= memInUse(MEM_STOREENTRY));
    }
    eventAdd("storeCleanup", storeCleanup, NULL, 0);
}

#if OLD_CODE
void
storeCleanupComplete(void *data, int retcode, int errcode)
{
    StoreEntry *e = data;
    storeUnlockObject(e);
    outvalid--;
    if (retcode == -2 && errcode == -2)
	return;
    if (!EBIT_TEST(e->flag, ENTRY_VALIDATED))
	storeRelease(e);
}
#endif

void
storeValidate(StoreEntry * e, STVLDCB callback, void *callback_data, void *tag)
{
    valid_ctrl_t *ctrlp;
    char *path;
    struct stat *sb;
#if !USE_ASYNC_IO
    int x;
#endif
    assert(!EBIT_TEST(e->flag, ENTRY_VALIDATED));
    if (e->swap_file_number < 0) {
	EBIT_CLR(e->flag, ENTRY_VALIDATED);
	callback(callback_data, 0, 0);
	return;
    }
    path = storeSwapFullPath(e->swap_file_number, NULL);
    sb = xmalloc(sizeof(struct stat));
    ctrlp = xmalloc(sizeof(valid_ctrl_t));
    ctrlp->sb = sb;
    ctrlp->e = e;
    ctrlp->callback = callback;
    ctrlp->callback_data = callback_data;
#if USE_ASYNC_IO
    aioStat(path, sb, storeValidateComplete, ctrlp, tag);
#else
    /*
     * When evaluating the actual arguments in a function call, the order
     * in which the arguments and the function expression are evaluated is
     * not specified;
     */
    x = stat(path, sb);
    storeValidateComplete(ctrlp, x, errno);
#endif
    return;
}

void
storeValidateComplete(void *data, int retcode, int errcode)
{
    valid_ctrl_t *ctrlp = data;
    struct stat *sb = ctrlp->sb;
    StoreEntry *e = ctrlp->e;
    char *path;

    if (retcode == -2 && errcode == -2) {
	xfree(sb);
	xfree(ctrlp);
	ctrlp->callback(ctrlp->callback_data, retcode, errcode);
	return;
    }
    if (retcode < 0 && errcode == EWOULDBLOCK) {
	path = storeSwapFullPath(e->swap_file_number, NULL);
	retcode = stat(path, sb);
    }
    if (retcode < 0 || sb->st_size == 0 || sb->st_size != e->object_len) {
	EBIT_CLR(e->flag, ENTRY_VALIDATED);
    } else {
	EBIT_SET(e->flag, ENTRY_VALIDATED);
	storeDirUpdateSwapSize(e->swap_file_number, e->object_len, 1);
    }
    errno = errcode;
    ctrlp->callback(ctrlp->callback_data, retcode, errcode);
    xfree(sb);
    xfree(ctrlp);
}

/* meta data recreated from disk image in swap directory */
static void
storeRebuildComplete(void)
{
    time_t r;
    time_t stop;
    stop = squid_curtime;
    r = stop - RebuildState.start;
    debug(20, 1) ("Finished rebuilding storage disk.\n");
    debug(20, 1) ("  %7d Entries read from previous logfile.\n",
	RebuildState.linecount);
    debug(20, 1) ("  %7d Entries scanned from swap files.\n",
	RebuildState.statcount);
    debug(20, 1) ("  %7d Invalid entries.\n", RebuildState.invalid);
    debug(20, 1) ("  %7d With invalid flags.\n", RebuildState.badflags);
    debug(20, 1) ("  %7d Objects loaded.\n", RebuildState.objcount);
    debug(20, 1) ("  %7d Objects expired.\n", RebuildState.expcount);
    debug(20, 1) ("  %7d Objects cancelled.\n", RebuildState.cancelcount);
    debug(20, 1) ("  %7d Duplicate URLs purged.\n", RebuildState.dupcount);
    debug(20, 1) ("  %7d Swapfile clashes avoided.\n", RebuildState.clashcount);
    debug(20, 1) ("  Took %d seconds (%6.1lf objects/sec).\n",
	r > 0 ? r : 0, (double) RebuildState.objcount / (r > 0 ? r : 1));
    debug(20, 1) ("Beginning Validation Procedure\n");
    eventAdd("storeCleanup", storeCleanup, NULL, 0);
}

void
storeRebuildStart(void)
{
    rebuild_dir *d;
    int clean = 0;
    int zero = 0;
    FILE *fp;
    int i;
    memset(&RebuildState, '\0', sizeof(RebuildState));
    RebuildState.start = squid_curtime;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	d = xcalloc(1, sizeof(rebuild_dir));
	d->dirn = i;
	d->speed = opt_foreground_rebuild ? 1 << 30 : 50;
	/*
	 * If the swap.state file exists in the cache_dir, then
	 * we'll use storeRebuildFromSwapLog(), otherwise we'll
	 * use storeRebuildFromDirectory() to open up each file
	 * and suck in the meta data.
	 */
	fp = storeDirOpenTmpSwapLog(i, &clean, &zero);
	if (fp == NULL || zero) {
	    d->rebuild_func = storeRebuildFromDirectory;
	} else {
	    d->rebuild_func = storeRebuildFromSwapLog;
	    d->log = fp;
	    d->clean = clean;
	    d->next = RebuildState.rebuild_dir;
	}
	RebuildState.rebuild_dir = d;
	if (!clean)
	    RebuildState.need_to_validate = 1;
	debug(20, 1) ("Rebuilding storage in Cache Dir #%d (%s)\n",
	    i, clean ? "CLEAN" : "DIRTY");
    }
    eventAdd("storeRebuild", storeRebuildADirectory, NULL, 0);
}
